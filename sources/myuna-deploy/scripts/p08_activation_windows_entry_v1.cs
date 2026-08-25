// Source-owned Windows-to-WSL transport and capture boundary for P08.
//
// This managed executable is materialized as a content-addressed release
// artifact.  It never constructs a plan and never calls a product role.  It
// verifies its own release binding, the fixed Windows/CLR/wsl.exe substrate,
// then uses CreateProcessW (not a shell) with inherited anonymous pipes and a
// kill-on-close Job Object.  The exact guest entrypoint owns /dev/null and the
// reviewed bootstrap child.
using System;
using System.Collections;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Web.Script.Serialization;

internal static class P08ActivationWindowsEntryV1
{
    private const uint STARTF_USESTDHANDLES = 0x00000100;
    private const uint CREATE_SUSPENDED = 0x00000004;
    private const uint CREATE_UNICODE_ENVIRONMENT = 0x00000400;
    private const uint EXTENDED_STARTUPINFO_PRESENT = 0x00080000;
    private const uint CREATE_NO_WINDOW = 0x08000000;
    private const uint HANDLE_FLAG_INHERIT = 0x00000001;
    private const uint JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x00002000;
    private const int JobObjectExtendedLimitInformation = 9;
    private const uint WAIT_OBJECT_0 = 0;
    private const uint WAIT_TIMEOUT = 258;
    private const uint INFINITE = 0xffffffff;
    private static readonly UIntPtr PROC_THREAD_ATTRIBUTE_HANDLE_LIST = new UIntPtr(0x00020002);
    private static readonly Regex Hex64 = new Regex("^[0-9a-f]{64}$", RegexOptions.CultureInvariant);

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct STARTUPINFO
    {
        public int cb;
        public string lpReserved;
        public string lpDesktop;
        public string lpTitle;
        public int dwX;
        public int dwY;
        public int dwXSize;
        public int dwYSize;
        public int dwXCountChars;
        public int dwYCountChars;
        public int dwFillAttribute;
        public uint dwFlags;
        public short wShowWindow;
        public short cbReserved2;
        public IntPtr lpReserved2;
        public IntPtr hStdInput;
        public IntPtr hStdOutput;
        public IntPtr hStdError;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct STARTUPINFOEX
    {
        public STARTUPINFO StartupInfo;
        public IntPtr lpAttributeList;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct PROCESS_INFORMATION
    {
        public IntPtr hProcess;
        public IntPtr hThread;
        public uint dwProcessId;
        public uint dwThreadId;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct SECURITY_ATTRIBUTES
    {
        public int nLength;
        public IntPtr lpSecurityDescriptor;
        public int bInheritHandle;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct IO_COUNTERS
    {
        public ulong ReadOperationCount;
        public ulong WriteOperationCount;
        public ulong OtherOperationCount;
        public ulong ReadTransferCount;
        public ulong WriteTransferCount;
        public ulong OtherTransferCount;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct JOBOBJECT_BASIC_LIMIT_INFORMATION
    {
        public long PerProcessUserTimeLimit;
        public long PerJobUserTimeLimit;
        public uint LimitFlags;
        public UIntPtr MinimumWorkingSetSize;
        public UIntPtr MaximumWorkingSetSize;
        public uint ActiveProcessLimit;
        public UIntPtr Affinity;
        public uint PriorityClass;
        public uint SchedulingClass;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct JOBOBJECT_EXTENDED_LIMIT_INFORMATION
    {
        public JOBOBJECT_BASIC_LIMIT_INFORMATION BasicLimitInformation;
        public IO_COUNTERS IoInfo;
        public UIntPtr ProcessMemoryLimit;
        public UIntPtr JobMemoryLimit;
        public UIntPtr PeakProcessMemoryUsed;
        public UIntPtr PeakJobMemoryUsed;
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CreatePipe(out IntPtr read, out IntPtr write, ref SECURITY_ATTRIBUTES attributes, uint size);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool SetHandleInformation(IntPtr handle, uint mask, uint flags);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern bool CreateProcessW(
        string applicationName,
        StringBuilder commandLine,
        IntPtr processAttributes,
        IntPtr threadAttributes,
        bool inheritHandles,
        uint creationFlags,
        IntPtr environment,
        string currentDirectory,
        ref STARTUPINFOEX startupInfo,
        out PROCESS_INFORMATION processInformation);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool InitializeProcThreadAttributeList(
        IntPtr attributeList,
        int attributeCount,
        int flags,
        ref IntPtr size);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool UpdateProcThreadAttribute(
        IntPtr attributeList,
        uint flags,
        UIntPtr attribute,
        IntPtr value,
        IntPtr size,
        IntPtr previousValue,
        IntPtr returnSize);

    [DllImport("kernel32.dll")]
    private static extern void DeleteProcThreadAttributeList(IntPtr attributeList);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr CreateJobObject(IntPtr attributes, string name);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool SetInformationJobObject(IntPtr job, int informationClass, IntPtr information, uint length);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool AssignProcessToJobObject(IntPtr job, IntPtr process);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern uint ResumeThread(IntPtr thread);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern uint WaitForSingleObject(IntPtr handle, uint milliseconds);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool GetExitCodeProcess(IntPtr process, out uint exitCode);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool TerminateJobObject(IntPtr job, uint exitCode);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool TerminateProcess(IntPtr process, uint exitCode);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CloseHandle(IntPtr handle);

    private sealed class Capture
    {
        public byte[] Stdout;
        public byte[] Stderr;
        public string ExitClass;
        public int ExitCode;
        public uint ChildPid;
        public long ElapsedMilliseconds;
    }

    private sealed class BoundedReader
    {
        private readonly FileStream stream;
        private readonly int limit;
        private readonly MemoryStream buffer = new MemoryStream();
        private readonly Thread thread;
        public volatile bool Oversize;
        public volatile bool Complete;

        public BoundedReader(IntPtr handle, int maximum)
        {
            stream = new FileStream(new Microsoft.Win32.SafeHandles.SafeFileHandle(handle, true), FileAccess.Read, 65536, false);
            limit = maximum;
            thread = new Thread(ReadLoop);
            thread.IsBackground = true;
        }

        public void Start() { thread.Start(); }
        public void Join(int milliseconds)
        {
            if (!thread.Join(milliseconds)) { throw new InvalidOperationException("capture_drain_timeout"); }
        }
        public byte[] Bytes() { return buffer.ToArray(); }

        private void ReadLoop()
        {
            byte[] block = new byte[65536];
            try
            {
                while (true)
                {
                    int count = stream.Read(block, 0, block.Length);
                    if (count == 0) { break; }
                    if (buffer.Length + count > limit)
                    {
                        int remaining = Math.Max(0, limit + 1 - (int)buffer.Length);
                        if (remaining > 0) { buffer.Write(block, 0, Math.Min(remaining, count)); }
                        Oversize = true;
                        break;
                    }
                    buffer.Write(block, 0, count);
                }
            }
            finally
            {
                stream.Dispose();
                Complete = true;
            }
        }
    }

    private static Dictionary<string, object> Dict(object value)
    {
        Dictionary<string, object> result = value as Dictionary<string, object>;
        if (result == null) { throw new InvalidOperationException("json_object_rejected"); }
        return result;
    }

    private static Dictionary<string, object> Nested(Dictionary<string, object> root, params string[] path)
    {
        Dictionary<string, object> current = root;
        foreach (string key in path)
        {
            if (!current.ContainsKey(key)) { throw new InvalidOperationException("json_key_rejected"); }
            current = Dict(current[key]);
        }
        return current;
    }

    private static string Text(Dictionary<string, object> root, string key)
    {
        if (!root.ContainsKey(key) || !(root[key] is string)) { throw new InvalidOperationException("json_text_rejected"); }
        return (string)root[key];
    }

    private static long Number(Dictionary<string, object> root, string key)
    {
        if (!root.ContainsKey(key) || root[key] is bool) { throw new InvalidOperationException("json_number_rejected"); }
        return Convert.ToInt64(root[key], CultureInfo.InvariantCulture);
    }

    private static bool Boolean(Dictionary<string, object> root, string key)
    {
        if (!root.ContainsKey(key) || !(root[key] is bool)) { throw new InvalidOperationException("json_boolean_rejected"); }
        return (bool)root[key];
    }

    private static string Quote(string value)
    {
        return new JavaScriptSerializer().Serialize(value);
    }

    private static string Canonical(object value)
    {
        if (value == null) { return "null"; }
        string text = value as string;
        if (text != null) { return Quote(text); }
        if (value is bool) { return ((bool)value) ? "true" : "false"; }
        Dictionary<string, object> dictionary = value as Dictionary<string, object>;
        if (dictionary != null)
        {
            List<string> keys = new List<string>(dictionary.Keys);
            keys.Sort(StringComparer.Ordinal);
            StringBuilder body = new StringBuilder("{");
            for (int index = 0; index < keys.Count; index++)
            {
                if (index != 0) { body.Append(','); }
                body.Append(Quote(keys[index]));
                body.Append(':');
                body.Append(Canonical(dictionary[keys[index]]));
            }
            body.Append('}');
            return body.ToString();
        }
        IEnumerable sequence = value as IEnumerable;
        if (sequence != null)
        {
            StringBuilder body = new StringBuilder("[");
            bool first = true;
            foreach (object item in sequence)
            {
                if (!first) { body.Append(','); }
                first = false;
                body.Append(Canonical(item));
            }
            body.Append(']');
            return body.ToString();
        }
        if (value is byte || value is short || value is int || value is long || value is sbyte || value is ushort || value is uint || value is ulong || value is decimal)
        {
            return Convert.ToString(value, CultureInfo.InvariantCulture);
        }
        throw new InvalidOperationException("json_type_rejected");
    }

    private static byte[] CanonicalBytes(object value)
    {
        return Encoding.ASCII.GetBytes(Canonical(value) + "\n");
    }

    private static string Sha256(byte[] bytes)
    {
        using (SHA256 algorithm = SHA256.Create())
        {
            StringBuilder value = new StringBuilder();
            foreach (byte item in algorithm.ComputeHash(bytes)) { value.Append(item.ToString("x2", CultureInfo.InvariantCulture)); }
            return value.ToString();
        }
    }

    private static string Sha256File(string path)
    {
        using (FileStream stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read))
        using (SHA256 algorithm = SHA256.Create())
        {
            StringBuilder value = new StringBuilder();
            foreach (byte item in algorithm.ComputeHash(stream)) { value.Append(item.ToString("x2", CultureInfo.InvariantCulture)); }
            return value.ToString();
        }
    }

    private static string ScopeIdentity(string contractDigest, string acceptanceScope, string backend, string root, string target, string launcherSha, string wslSha)
    {
        string body = "myuna.p08-windows-wsl-entry-scope.v1\n" + contractDigest + "\n" + acceptanceScope + "\n" + backend + "\n" + root + "\n" + target + "\n" + launcherSha + "\n" + wslSha + "\n";
        return Sha256(Encoding.UTF8.GetBytes(body));
    }

    private static string CommandLine(string executable, IList<string> arguments)
    {
        StringBuilder value = new StringBuilder(WindowsQuote(executable));
        foreach (string argument in arguments) { value.Append(' ').Append(WindowsQuote(argument)); }
        return value.ToString();
    }

    private static string WindowsQuote(string value)
    {
        if (value.Length != 0 && value.IndexOfAny(new char[] { ' ', '\t', '"' }) < 0) { return value; }
        StringBuilder quoted = new StringBuilder("\"");
        int slashes = 0;
        foreach (char item in value)
        {
            if (item == '\\') { slashes++; continue; }
            if (item == '"')
            {
                quoted.Append('\\', slashes * 2 + 1).Append('"');
                slashes = 0;
                continue;
            }
            quoted.Append('\\', slashes).Append(item);
            slashes = 0;
        }
        quoted.Append('\\', slashes * 2).Append('"');
        return quoted.ToString();
    }

    private static IntPtr EnvironmentBlock(IDictionary<string, string> environment)
    {
        List<string> keys = new List<string>(environment.Keys);
        keys.Sort(StringComparer.OrdinalIgnoreCase);
        StringBuilder body = new StringBuilder();
        foreach (string key in keys) { body.Append(key).Append('=').Append(environment[key]).Append('\0'); }
        body.Append('\0');
        return Marshal.StringToHGlobalUni(body.ToString());
    }

    private static Capture RunDirect(string executable, IList<string> arguments, string cwd, IDictionary<string, string> environment, byte[] stdinBytes, int timeoutSeconds, int stdoutLimit, int stderrLimit)
    {
        SECURITY_ATTRIBUTES attributes = new SECURITY_ATTRIBUTES();
        attributes.nLength = Marshal.SizeOf(attributes);
        attributes.bInheritHandle = 1;
        IntPtr stdoutRead = IntPtr.Zero;
        IntPtr stdoutWrite = IntPtr.Zero;
        IntPtr stderrRead = IntPtr.Zero;
        IntPtr stderrWrite = IntPtr.Zero;
        IntPtr stdinRead = IntPtr.Zero;
        IntPtr stdinWrite = IntPtr.Zero;
        IntPtr block = IntPtr.Zero;
        IntPtr job = IntPtr.Zero;
        IntPtr limitBuffer = IntPtr.Zero;
        IntPtr attributeList = IntPtr.Zero;
        IntPtr handleList = IntPtr.Zero;
        PROCESS_INFORMATION process = new PROCESS_INFORMATION();
        bool processCreated = false;
        bool jobAssigned = false;
        bool attributeListInitialized = false;
        BoundedReader stdout = null;
        BoundedReader stderr = null;
        Stopwatch elapsed = Stopwatch.StartNew();
        try
        {
            if (!CreatePipe(out stdoutRead, out stdoutWrite, ref attributes, 0) ||
                !CreatePipe(out stderrRead, out stderrWrite, ref attributes, 0) ||
                !CreatePipe(out stdinRead, out stdinWrite, ref attributes, 0) ||
                !SetHandleInformation(stdoutRead, HANDLE_FLAG_INHERIT, 0) ||
                !SetHandleInformation(stderrRead, HANDLE_FLAG_INHERIT, 0) ||
                !SetHandleInformation(stdinWrite, HANDLE_FLAG_INHERIT, 0))
            {
                throw new InvalidOperationException("transport_pipe_rejected");
            }

            STARTUPINFOEX startup = new STARTUPINFOEX();
            startup.StartupInfo.cb = Marshal.SizeOf(typeof(STARTUPINFOEX));
            startup.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
            startup.StartupInfo.hStdInput = stdinRead;
            startup.StartupInfo.hStdOutput = stdoutWrite;
            startup.StartupInfo.hStdError = stderrWrite;
            IntPtr attributeSize = IntPtr.Zero;
            InitializeProcThreadAttributeList(IntPtr.Zero, 1, 0, ref attributeSize);
            if (attributeSize == IntPtr.Zero) { throw new InvalidOperationException("transport_handle_list_rejected"); }
            attributeList = Marshal.AllocHGlobal(attributeSize);
            if (!InitializeProcThreadAttributeList(attributeList, 1, 0, ref attributeSize))
            {
                throw new InvalidOperationException("transport_handle_list_rejected");
            }
            attributeListInitialized = true;
            handleList = Marshal.AllocHGlobal(IntPtr.Size * 3);
            Marshal.WriteIntPtr(handleList, 0, stdinRead);
            Marshal.WriteIntPtr(handleList, IntPtr.Size, stdoutWrite);
            Marshal.WriteIntPtr(handleList, IntPtr.Size * 2, stderrWrite);
            if (!UpdateProcThreadAttribute(
                attributeList,
                0,
                PROC_THREAD_ATTRIBUTE_HANDLE_LIST,
                handleList,
                new IntPtr(IntPtr.Size * 3),
                IntPtr.Zero,
                IntPtr.Zero))
            {
                throw new InvalidOperationException("transport_handle_list_rejected");
            }
            startup.lpAttributeList = attributeList;

            block = EnvironmentBlock(environment);
            job = CreateJobObject(IntPtr.Zero, null);
            if (job == IntPtr.Zero) { throw new InvalidOperationException("transport_job_rejected"); }
            JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits = new JOBOBJECT_EXTENDED_LIMIT_INFORMATION();
            limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
            int limitSize = Marshal.SizeOf(limits);
            limitBuffer = Marshal.AllocHGlobal(limitSize);
            Marshal.StructureToPtr(limits, limitBuffer, false);
            if (!SetInformationJobObject(job, JobObjectExtendedLimitInformation, limitBuffer, (uint)limitSize))
            {
                throw new InvalidOperationException("transport_job_rejected");
            }
            if (!CreateProcessW(
                executable,
                new StringBuilder(CommandLine(executable, arguments)),
                IntPtr.Zero,
                IntPtr.Zero,
                true,
                CREATE_SUSPENDED | CREATE_UNICODE_ENVIRONMENT | CREATE_NO_WINDOW | EXTENDED_STARTUPINFO_PRESENT,
                block,
                cwd,
                ref startup,
                out process))
            {
                throw new InvalidOperationException("transport_process_rejected");
            }
            processCreated = true;
            CloseHandle(stdoutWrite); stdoutWrite = IntPtr.Zero;
            CloseHandle(stderrWrite); stderrWrite = IntPtr.Zero;
            CloseHandle(stdinRead); stdinRead = IntPtr.Zero;
            if (stdinBytes == null)
            {
                CloseHandle(stdinWrite); stdinWrite = IntPtr.Zero;
            }
            else
            {
                using (FileStream input = new FileStream(new Microsoft.Win32.SafeHandles.SafeFileHandle(stdinWrite, true), FileAccess.Write, 4096, false))
                {
                    stdinWrite = IntPtr.Zero;
                    input.Write(stdinBytes, 0, stdinBytes.Length);
                    input.Flush();
                }
            }
            if (!AssignProcessToJobObject(job, process.hProcess))
            {
                TerminateProcess(process.hProcess, 125);
                WaitForSingleObject(process.hProcess, 2000);
                throw new InvalidOperationException("transport_process_rejected");
            }
            jobAssigned = true;
            if (ResumeThread(process.hThread) == 0xffffffff)
            {
                TerminateJobObject(job, 125);
                WaitForSingleObject(process.hProcess, 2000);
                throw new InvalidOperationException("transport_process_rejected");
            }
            CloseHandle(process.hThread);
            process.hThread = IntPtr.Zero;
            stdout = new BoundedReader(stdoutRead, stdoutLimit);
            stdoutRead = IntPtr.Zero;
            stderr = new BoundedReader(stderrRead, stderrLimit);
            stderrRead = IntPtr.Zero;
            stdout.Start(); stderr.Start();
            string exitClass = "exit";
            uint wait;
            while (true)
            {
                wait = WaitForSingleObject(process.hProcess, 50);
                if (wait == WAIT_OBJECT_0) { break; }
                if (wait != WAIT_TIMEOUT) { exitClass = "wait_failed"; TerminateJobObject(job, 125); break; }
                if (stdout.Oversize) { exitClass = "stdout_oversize"; TerminateJobObject(job, 125); break; }
                if (stderr.Oversize) { exitClass = "stderr_oversize"; TerminateJobObject(job, 125); break; }
                if (elapsed.Elapsed.TotalSeconds >= timeoutSeconds) { exitClass = "hard_timeout"; TerminateJobObject(job, 125); break; }
            }
            WaitForSingleObject(process.hProcess, 2000);
            stdout.Join(2000); stderr.Join(2000);
            uint rawExit;
            if (!GetExitCodeProcess(process.hProcess, out rawExit)) { rawExit = 125; }
            CloseHandle(process.hProcess);
            process.hProcess = IntPtr.Zero;
            return new Capture
            {
                Stdout = stdout.Bytes(),
                Stderr = stderr.Bytes(),
                ExitClass = exitClass,
                ExitCode = unchecked((int)rawExit),
                ChildPid = process.dwProcessId,
                ElapsedMilliseconds = elapsed.ElapsedMilliseconds,
            };
        }
        finally
        {
            elapsed.Stop();
            if (processCreated && process.hProcess != IntPtr.Zero)
            {
                if (jobAssigned) { TerminateJobObject(job, 125); }
                else { TerminateProcess(process.hProcess, 125); }
                WaitForSingleObject(process.hProcess, 2000);
            }
            if (stdout != null && !stdout.Complete) { try { stdout.Join(2000); } catch { } }
            if (stderr != null && !stderr.Complete) { try { stderr.Join(2000); } catch { } }
            if (process.hThread != IntPtr.Zero) { CloseHandle(process.hThread); }
            if (process.hProcess != IntPtr.Zero) { CloseHandle(process.hProcess); }
            if (stdinRead != IntPtr.Zero) { CloseHandle(stdinRead); }
            if (stdinWrite != IntPtr.Zero) { CloseHandle(stdinWrite); }
            if (stdoutRead != IntPtr.Zero) { CloseHandle(stdoutRead); }
            if (stderrRead != IntPtr.Zero) { CloseHandle(stderrRead); }
            if (stdoutWrite != IntPtr.Zero) { CloseHandle(stdoutWrite); }
            if (stderrWrite != IntPtr.Zero) { CloseHandle(stderrWrite); }
            if (attributeListInitialized) { DeleteProcThreadAttributeList(attributeList); }
            if (handleList != IntPtr.Zero) { Marshal.FreeHGlobal(handleList); }
            if (attributeList != IntPtr.Zero) { Marshal.FreeHGlobal(attributeList); }
            if (block != IntPtr.Zero) { Marshal.FreeHGlobal(block); }
            if (limitBuffer != IntPtr.Zero) { Marshal.FreeHGlobal(limitBuffer); }
            if (job != IntPtr.Zero) { CloseHandle(job); }
        }
    }

    private static bool ByteEqual(byte[] left, byte[] right)
    {
        if (left.Length != right.Length) { return false; }
        int difference = 0;
        for (int i = 0; i < left.Length; i++) { difference |= left[i] ^ right[i]; }
        return difference == 0;
    }

    private static Dictionary<string, object> ParseCanonical(byte[] bytes)
    {
        string text = new UTF8Encoding(false, true).GetString(bytes);
        object parsed = new JavaScriptSerializer().DeserializeObject(text);
        Dictionary<string, object> value = Dict(parsed);
        if (!ByteEqual(bytes, CanonicalBytes(value))) { throw new InvalidOperationException("canonical_result_rejected"); }
        return value;
    }

    private static bool ValidateTopLevelResult(Dictionary<string, object> result, Dictionary<string, object> contract, string acceptanceScope, string entryIdentity)
    {
        string[] expected = new string[] { "acceptance_scope_digest", "architecture", "canonical_child_result_digest", "capture_digest", "child_plan_digest", "child_preclaim_category", "child_preclaim_cause_source", "child_preclaim_mutation_state", "child_preclaim_phase", "child_preclaim_subcategory", "child_product_state", "child_terminal_status", "contract_digest", "entry_identity", "failure_category", "intent_digest", "raw_output_included", "result_digest", "retry_authorized", "schema", "stage", "status" };
        List<string> observed = new List<string>(result.Keys); observed.Sort(StringComparer.Ordinal);
        if (observed.Count != expected.Length) { return false; }
        for (int i = 0; i < expected.Length; i++) { if (observed[i] != expected[i]) { return false; } }
        Dictionary<string, object> schemas = Nested(contract, "schemas");
        Dictionary<string, object> topLevel = Nested(contract, "launcher", "top_level_entry");
        if (Text(result, "schema") != Text(schemas, "top_level_entry_result") ||
            Text(result, "architecture") != Text(contract, "architecture") ||
            Text(result, "contract_digest") != Text(contract, "contract_digest") ||
            Text(result, "acceptance_scope_digest") != acceptanceScope ||
            Text(result, "entry_identity") != entryIdentity ||
            Text(result, "stage") != "source_owned_top_level_capture" ||
            Boolean(result, "raw_output_included") || Boolean(result, "retry_authorized")) { return false; }
        object failure = result["failure_category"];
        string failureText = failure as string;
        object[] allowedFailures = topLevel["result_failure_categories"] as object[];
        if (allowedFailures == null) { return false; }
        bool failureAllowed = failure == null;
        foreach (object allowed in allowedFailures)
        {
            if (failureText != null && allowed as string == failureText) { failureAllowed = true; }
        }
        if (!failureAllowed) { return false; }
        string resultStatus = Text(result, "status");
        if (resultStatus != "accepted" && resultStatus != "hard_stop" && resultStatus != "rejected" && resultStatus != "indeterminate") { return false; }
        string productState = Text(result, "child_product_state");
        if (productState != "accepted" && productState != "predecessor_restored" && productState != "unmodified" && productState != "unknown") { return false; }
        string[] nullableHex = new string[] { "canonical_child_result_digest", "capture_digest", "child_plan_digest", "intent_digest" };
        foreach (string key in nullableHex)
        {
            object raw = result[key];
            string value = raw as string;
            if (raw != null && (value == null || !Hex64.IsMatch(value))) { return false; }
        }
        object preclaimPhaseRaw = result["child_preclaim_phase"];
        object preclaimCategoryRaw = result["child_preclaim_category"];
        object preclaimCauseSourceRaw = result["child_preclaim_cause_source"];
        object preclaimSubcategoryRaw = result["child_preclaim_subcategory"];
        object preclaimMutationRaw = result["child_preclaim_mutation_state"];
        bool hasPreclaim = preclaimPhaseRaw != null || preclaimCategoryRaw != null || preclaimCauseSourceRaw != null || preclaimSubcategoryRaw != null || preclaimMutationRaw != null;
        Dictionary<string, object> preclaim = Nested(topLevel, "preclaim");
        object[] rows = preclaim["ordered_phases"] as object[];
        if (rows == null) { return false; }
        bool failureIsPreclaimCategory = false;
        foreach (object rawRow in rows)
        {
            Dictionary<string, object> row = Dict(rawRow);
            object[] categories = row["rejection_categories"] as object[];
            if (categories == null) { return false; }
            foreach (object rawCategory in categories)
            {
                if (failureText != null && rawCategory as string == failureText) { failureIsPreclaimCategory = true; }
            }
        }
        if (failureText != null && Text(preclaim, "unexpected_category") == failureText) { failureIsPreclaimCategory = true; }
        if (failureIsPreclaimCategory != hasPreclaim) { return false; }
        if (hasPreclaim)
        {
            string preclaimPhase = preclaimPhaseRaw as string;
            string preclaimCategory = preclaimCategoryRaw as string;
            string preclaimCauseSource = preclaimCauseSourceRaw as string;
            string preclaimSubcategory = preclaimSubcategoryRaw as string;
            string preclaimMutation = preclaimMutationRaw as string;
            if (preclaimPhase == null || preclaimCategory == null || preclaimCauseSource == null || preclaimSubcategory == null || preclaimMutation == null || failureText != preclaimCategory) { return false; }
            if (preclaimMutation != Text(preclaim, "product_mutation_state")) { return false; }
            bool phaseCategoryAllowed = false;
            bool phaseSubcategoryAllowed = false;
            foreach (object rawRow in rows)
            {
                Dictionary<string, object> row = Dict(rawRow);
                if (Text(row, "phase") != preclaimPhase) { continue; }
                object[] categories = row["rejection_categories"] as object[];
                if (categories == null) { return false; }
                foreach (object rawCategory in categories)
                {
                    if (rawCategory as string == preclaimCategory) { phaseCategoryAllowed = true; }
                }
                if (Text(preclaim, "unexpected_category") == preclaimCategory) { phaseCategoryAllowed = true; }
                Dictionary<string, object> sources = Nested(row, "subcategory_sources");
                if (!sources.ContainsKey(preclaimCauseSource)) { return false; }
                object[] subcategories = sources[preclaimCauseSource] as object[];
                if (subcategories == null) { return false; }
                foreach (object rawSubcategory in subcategories)
                {
                    if (rawSubcategory as string == preclaimSubcategory) { phaseSubcategoryAllowed = true; }
                }
            }
            string expectedStatus = preclaimCategory == Text(preclaim, "unexpected_category") ? Text(preclaim, "unexpected_status") : Text(preclaim, "typed_status");
            if (!phaseCategoryAllowed || !phaseSubcategoryAllowed || Text(result, "status") != expectedStatus || Text(result, "child_product_state") != "unmodified" || result["child_terminal_status"] != null || result["child_plan_digest"] != null || result["intent_digest"] == null || result["canonical_child_result_digest"] == null || result["capture_digest"] == null) { return false; }
        }
        if ((resultStatus == "accepted" || resultStatus == "hard_stop") && failure != null) { return false; }
        if ((resultStatus == "rejected" || resultStatus == "indeterminate") && failure == null) { return false; }
        if ((resultStatus == "accepted" || resultStatus == "hard_stop") && (result["intent_digest"] == null || result["capture_digest"] == null || result["canonical_child_result_digest"] == null || result["child_terminal_status"] == null)) { return false; }
        if ((resultStatus == "rejected" || resultStatus == "indeterminate") && result["capture_digest"] == null && result["canonical_child_result_digest"] != null) { return false; }
        Dictionary<string, object> unsigned = new Dictionary<string, object>(result);
        string resultDigest = Text(unsigned, "result_digest"); unsigned.Remove("result_digest");
        return Hex64.IsMatch(resultDigest) && resultDigest == Sha256(CanonicalBytes(unsigned));
    }

    private static bool ValidatePersistResult(Dictionary<string, object> result, Dictionary<string, object> contract, string acceptanceScope, string entryIdentity, string captureDigest)
    {
        string[] expected = new string[] { "acceptance_scope_digest", "architecture", "canonical_status", "capture_digest", "contract_digest", "entry_identity", "raw_output_included", "result_digest", "retry_authorized", "schema", "status" };
        List<string> observed = new List<string>(result.Keys); observed.Sort(StringComparer.Ordinal);
        if (observed.Count != expected.Length) { return false; }
        for (int i = 0; i < expected.Length; i++) { if (observed[i] != expected[i]) { return false; } }
        Dictionary<string, object> schemas = Nested(contract, "schemas");
        if (Text(result, "schema") != Text(schemas, "windows_wsl_capture_persist_result") ||
            Text(result, "architecture") != Text(contract, "architecture") ||
            Text(result, "contract_digest") != Text(contract, "contract_digest") ||
            Text(result, "acceptance_scope_digest") != acceptanceScope ||
            Text(result, "entry_identity") != entryIdentity ||
            Text(result, "capture_digest") != captureDigest ||
            (Text(result, "canonical_status") != "complete" && Text(result, "canonical_status") != "indeterminate") ||
            Text(result, "status") != "persisted" ||
            Boolean(result, "raw_output_included") || Boolean(result, "retry_authorized")) { return false; }
        Dictionary<string, object> unsigned = new Dictionary<string, object>(result);
        string resultDigest = Text(unsigned, "result_digest"); unsigned.Remove("result_digest");
        return Hex64.IsMatch(resultDigest) && resultDigest == Sha256(CanonicalBytes(unsigned));
    }

    private static bool StderrAllowed(byte[] stderr, Dictionary<string, object> transport)
    {
        if (stderr.Length == 0) { return true; }
        object classificationsRaw;
        if (!transport.TryGetValue("host_stderr_classifications", out classificationsRaw)) { return false; }
        object[] classifications = classificationsRaw as object[];
        if (classifications == null) { return false; }
        foreach (object item in classifications)
        {
            Dictionary<string, object> row = Dict(item);
            if (Number(row, "size") == stderr.Length && Text(row, "sha256") == Sha256(stderr)) { return true; }
        }
        return false;
    }

    private static int Main(string[] args)
    {
        string failureStage = "source_owned_windows_arguments";
        try
        {
            string[] names = new string[] { "--activation-contract", "--activation-contract-linux", "--activation-root", "--activation-backend", "--activation-target-source", "--acceptance-scope-digest" };
            if (args.Length != names.Length * 2) { throw new InvalidOperationException("host_arguments_rejected"); }
            Dictionary<string, string> values = new Dictionary<string, string>(StringComparer.Ordinal);
            for (int i = 0; i < names.Length; i++)
            {
                if (args[i * 2] != names[i]) { throw new InvalidOperationException("host_arguments_rejected"); }
                values[names[i]] = args[i * 2 + 1];
            }
            if (!Hex64.IsMatch(values["--acceptance-scope-digest"]) ||
                (values["--activation-backend"] != "synthetic" && values["--activation-backend"] != "systemd") ||
                !values["--activation-root"].StartsWith("/", StringComparison.Ordinal) ||
                !values["--activation-target-source"].StartsWith("/", StringComparison.Ordinal) ||
                !values["--activation-contract-linux"].StartsWith("/", StringComparison.Ordinal)) { throw new InvalidOperationException("host_arguments_rejected"); }
            failureStage = "source_owned_windows_contract";
            string executable = Path.GetFullPath(Assembly.GetExecutingAssembly().Location);
            string releaseRoot = Directory.GetParent(Directory.GetParent(executable).FullName).FullName;
            string contractPath = Path.GetFullPath(values["--activation-contract"]);
            string linuxTarget = values["--activation-target-source"].TrimEnd('/');
            int linuxTargetSeparator = linuxTarget.LastIndexOf('/');
            string linuxTargetIdentity = linuxTargetSeparator < 0 ? linuxTarget : linuxTarget.Substring(linuxTargetSeparator + 1);
            if (!String.Equals(Environment.CurrentDirectory.TrimEnd('\\'), releaseRoot.TrimEnd('\\'), StringComparison.OrdinalIgnoreCase) ||
                !String.Equals(contractPath, Path.Combine(releaseRoot, "contracts", "P08_ACTIVATION_CONTRACT.json"), StringComparison.OrdinalIgnoreCase) ||
                !Hex64.IsMatch(linuxTargetIdentity) ||
                !String.Equals(Path.GetFileName(releaseRoot), linuxTargetIdentity, StringComparison.Ordinal)) { throw new InvalidOperationException("host_cwd_rejected"); }
            byte[] contractBytes = File.ReadAllBytes(contractPath);
            Dictionary<string, object> contract = ParseCanonical(contractBytes);
            Dictionary<string, object> top = Nested(contract, "launcher", "top_level_entry");
            Dictionary<string, object> host = Nested(top, "host_launcher");
            Dictionary<string, object> transport = Nested(top, "transport");
            failureStage = "source_owned_windows_identity";
            string expectedExecutable = Path.Combine(releaseRoot, Text(host, "artifact_path").Replace('/', '\\'));
            if (!String.Equals(executable, expectedExecutable, StringComparison.OrdinalIgnoreCase) ||
                new FileInfo(executable).Length != Number(host, "size") ||
                Sha256File(executable) != Text(host, "sha256") ||
                Sha256File(Path.Combine(releaseRoot, Text(host, "source_path").Replace('/', '\\'))) != Text(host, "source_sha256") ||
                Environment.Version.ToString() != Text(host, "clr_version") ||
                !String.Equals(typeof(object).Assembly.Location, Text(host, "mscorlib_path"), StringComparison.OrdinalIgnoreCase) ||
                new FileInfo(typeof(object).Assembly.Location).Length != Number(host, "mscorlib_size") ||
                Sha256File(typeof(object).Assembly.Location) != Text(host, "mscorlib_sha256")) { throw new InvalidOperationException("host_source_identity_rejected"); }
            failureStage = "source_owned_windows_transport";
            string wsl = Text(transport, "windows_path");
            failureStage = "source_owned_windows_transport_size";
            if (new FileInfo(wsl).Length != Number(transport, "size")) { throw new InvalidOperationException("host_transport_identity_rejected"); }
            failureStage = "source_owned_windows_transport_digest";
            if (Sha256File(wsl) != Text(transport, "sha256")) { throw new InvalidOperationException("host_transport_identity_rejected"); }
            failureStage = "source_owned_windows_transport_version";
            if (Text(transport, "version_authority") != "pe_bytes_sha256") { throw new InvalidOperationException("host_transport_identity_rejected"); }
            string identity = ScopeIdentity(Text(contract, "contract_digest"), values["--acceptance-scope-digest"], values["--activation-backend"], values["--activation-root"], values["--activation-target-source"], Text(host, "sha256"), Text(transport, "sha256"));
            Dictionary<string, string> guestEnvironment = new Dictionary<string, string>(StringComparer.Ordinal) {
                { "LANG", "C.UTF-8" }, { "LC_ALL", "C.UTF-8" }, { "PATH", "/usr/sbin:/usr/bin:/sbin:/bin" },
                { "PYTHONDONTWRITEBYTECODE", "1" },
                { "PYTHONPATH", values["--activation-target-source"] + "/scripts:" + values["--activation-target-source"] + "/src" },
                { "MYUNA_P08_WINDOWS_HOST_ENTRY_IDENTITY", identity }
            };
            List<string> guest = new List<string>(); guest.Add("/usr/bin/env"); guest.Add("-i");
            List<string> guestKeys = new List<string>(guestEnvironment.Keys); guestKeys.Sort(StringComparer.Ordinal);
            foreach (string key in guestKeys) { guest.Add(key + "=" + guestEnvironment[key]); }
            guest.Add("/usr/bin/python3"); guest.Add("-B"); guest.Add("-P"); guest.Add("-S"); guest.Add("-m"); guest.Add("p08_activation_top_level_entry_v1");
            guest.Add("--activation-contract"); guest.Add(values["--activation-contract-linux"]);
            guest.Add("--activation-root"); guest.Add(values["--activation-root"]);
            guest.Add("--activation-backend"); guest.Add(values["--activation-backend"]);
            guest.Add("--activation-target-source"); guest.Add(values["--activation-target-source"]);
            guest.Add("--acceptance-scope-digest"); guest.Add(values["--acceptance-scope-digest"]);
            List<string> wslArguments = new List<string>();
            wslArguments.Add("--distribution"); wslArguments.Add(Text(transport, "distribution")); wslArguments.Add("--user"); wslArguments.Add("root"); wslArguments.Add("--cd"); wslArguments.Add(values["--activation-target-source"]); wslArguments.Add("--exec"); wslArguments.AddRange(guest);
            Dictionary<string, string> hostEnvironment = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase) {
                { "SystemRoot", Environment.GetEnvironmentVariable("SystemRoot") ?? "C:\\WINDOWS" },
                { "WINDIR", Environment.GetEnvironmentVariable("WINDIR") ?? "C:\\WINDOWS" },
                { "PATH", "C:\\WINDOWS\\System32" }, { "WSLENV", "" }
            };
            failureStage = "source_owned_windows_capture";
            Capture capture = RunDirect(wsl, wslArguments, releaseRoot, hostEnvironment, null, Convert.ToInt32(Number(host, "hard_deadline_seconds")), Convert.ToInt32(Number(host, "stdout_limit")), Convert.ToInt32(Number(host, "stderr_limit")));
            Dictionary<string, object> result = null;
            bool valid = false;
            try { result = ParseCanonical(capture.Stdout); valid = ValidateTopLevelResult(result, contract, values["--acceptance-scope-digest"], identity); } catch { valid = false; }
            bool stderrAllowed = StderrAllowed(capture.Stderr, transport);
            Dictionary<string, object> captureBody = new Dictionary<string, object> {
                { "schema", Text(Nested(contract, "schemas"), "windows_wsl_capture") }, { "architecture", Text(contract, "architecture") },
                { "contract_digest", Text(contract, "contract_digest") }, { "acceptance_scope_digest", values["--acceptance-scope-digest"] },
                { "entry_identity", identity }, { "host_launcher_sha256", Text(host, "sha256") }, { "wsl_sha256", Text(transport, "sha256") },
                { "child_pid", (long)capture.ChildPid }, { "exit_class", capture.ExitClass }, { "returncode", capture.ExitCode },
                { "elapsed_ms", capture.ElapsedMilliseconds }, { "stdout_size", capture.Stdout.Length }, { "stdout_sha256", Sha256(capture.Stdout) },
                { "stderr_size", capture.Stderr.Length }, { "stderr_sha256", Sha256(capture.Stderr) },
                { "canonical_result_digest", valid ? Text(result, "result_digest") : null }, { "canonical_status", valid ? "complete" : "indeterminate" },
                { "stderr_classification_allowed", stderrAllowed }, { "raw_output_retained", false }, { "orphan_count", 0 }
            };
            Dictionary<string, object> captureFile = new Dictionary<string, object>(captureBody);
            captureFile["capture_digest"] = Sha256(CanonicalBytes(captureBody));
            failureStage = "source_owned_windows_persistence";
            byte[] captureFileBytes = CanonicalBytes(captureFile);
            List<string> persistGuest = new List<string>(); persistGuest.Add("/usr/bin/env"); persistGuest.Add("-i");
            foreach (string key in guestKeys) { persistGuest.Add(key + "=" + guestEnvironment[key]); }
            persistGuest.Add("/usr/bin/python3"); persistGuest.Add("-B"); persistGuest.Add("-P"); persistGuest.Add("-S"); persistGuest.Add("-m");
            persistGuest.Add(Path.GetFileNameWithoutExtension(Text(top, "capture_persist_entrypoint")));
            persistGuest.Add("--activation-contract"); persistGuest.Add(values["--activation-contract-linux"]);
            persistGuest.Add("--activation-root"); persistGuest.Add(values["--activation-root"]);
            persistGuest.Add("--activation-backend"); persistGuest.Add(values["--activation-backend"]);
            persistGuest.Add("--activation-target-source"); persistGuest.Add(values["--activation-target-source"]);
            persistGuest.Add("--acceptance-scope-digest"); persistGuest.Add(values["--acceptance-scope-digest"]);
            persistGuest.Add("--entry-identity"); persistGuest.Add(identity);
            List<string> persistWslArguments = new List<string>();
            persistWslArguments.Add("--distribution"); persistWslArguments.Add(Text(transport, "distribution")); persistWslArguments.Add("--user"); persistWslArguments.Add("root"); persistWslArguments.Add("--cd"); persistWslArguments.Add(values["--activation-target-source"]); persistWslArguments.Add("--exec"); persistWslArguments.AddRange(persistGuest);
            Capture persistence = RunDirect(wsl, persistWslArguments, releaseRoot, hostEnvironment, captureFileBytes, Convert.ToInt32(Number(top, "capture_persist_hard_deadline_seconds")), Convert.ToInt32(Number(host, "stdout_limit")), Convert.ToInt32(Number(host, "stderr_limit")));
            Dictionary<string, object> persistResult = null;
            bool persistValid = false;
            try { persistResult = ParseCanonical(persistence.Stdout); persistValid = ValidatePersistResult(persistResult, contract, values["--acceptance-scope-digest"], identity, Text(captureFile, "capture_digest")); } catch { persistValid = false; }
            if (!persistValid || persistence.ExitClass != "exit" || persistence.ExitCode != 0 || !StderrAllowed(persistence.Stderr, transport)) { throw new InvalidOperationException("host_capture_persistence_rejected"); }
            failureStage = "source_owned_windows_result";
            if (!valid || !stderrAllowed || capture.ExitClass != "exit") { throw new InvalidOperationException("host_capture_rejected"); }
            Console.OpenStandardOutput().Write(capture.Stdout, 0, capture.Stdout.Length);
            string status = Text(result, "status");
            return status == "accepted" ? 0 : (status == "hard_stop" || status == "rejected" ? 2 : 1);
        }
        catch
        {
            byte[] fallback = Encoding.ASCII.GetBytes("{\"product_state\":\"unknown\",\"raw_output_included\":false,\"retry_authorized\":false,\"schema\":\"myuna.p08-activation-supervisor-entry.v1\",\"stage\":\"" + failureStage + "\",\"status\":\"indeterminate\"}\n");
            Console.OpenStandardOutput().Write(fallback, 0, fallback.Length);
            return 1;
        }
    }
}
