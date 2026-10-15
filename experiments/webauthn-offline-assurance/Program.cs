using System.Text.Json;

namespace WebAuthn.OfflineAssurance;

internal static class Program
{
    private static int Main(string[] args)
    {
        try
        {
            if (args.Length == 4 && args[0] is "--candidate-create" or "--candidate-audit")
            {
                if (args[0] == "--candidate-create") SyntheticCandidate.Create(args[1], args[2], args[3]);
                SyntheticCandidate.Audit(args[1], args[2], args[3]);
                Console.WriteLine(JsonSerializer.Serialize(new { schemaVersion = 1, designation = "SYNTHETIC_ONLY", verificationStatus = "LOCAL_CONTENT_CONSISTENT_PRODUCER_UNAUTHENTICATED", productionAuthorization = "DEFAULT_DENY", realCredentialOperations = "NO_GO" }, JsonDefaults.Options));
                return 0;
            }
            if (args.Length == 3 && args[0] == "--policy-check")
            {
                var result = AssuranceVerifier.PolicyCheck(ReadBounded(args[1]), ReadBounded(args[2]));
                Console.WriteLine(result.Json);
                return result.ExitCode;
            }
            if (args.Length == 6 && args[0] == "--report")
            {
                var revision = args[4] != "-" ? args[4] : null;
                var result = AssuranceVerifier.Report(ReadBounded(args[1]), ReadBounded(args[2]), ReadBounded(args[3]), revision, args[5]);
                Console.WriteLine(result.Json);
                return result.ExitCode;
            }
            if (args.Length == 5 && args[0] == "--self-test")
            {
                var result = OfflineAssuranceSelfTests.Run(ReadBounded(args[1]), ReadBounded(args[2]), args[3], args[4]);
                Console.WriteLine(JsonSerializer.Serialize(result, JsonDefaults.Options));
                return result.Failures == 0 ? 0 : 1;
            }
            Console.Error.WriteLine("usage: --policy-check <manifest> <registry> | --report <manifest> <registry> <evidence> <source-revision|-> <repository-root> | --self-test <manifest> <registry> <fixture-dir> <repository-root> | --candidate-create <repository-root> <base-revision> <new-directory> | --candidate-audit <repository-root> <base-revision> <candidate-directory>");
            return 64;
        }
        catch (AssuranceInputException error)
        {
            Console.WriteLine(JsonSerializer.Serialize(new { reportSchemaVersion = 1, verificationStatus = "INPUT_REJECTED", errorCategory = error.Category }, JsonDefaults.Options));
            return 2;
        }
        catch (Exception)
        {
            Console.WriteLine(JsonSerializer.Serialize(new { reportSchemaVersion = 1, verificationStatus = "INPUT_REJECTED", errorCategory = "INPUT_READ_FAILED" }, JsonDefaults.Options));
            return 2;
        }
    }

    private static string ReadBounded(string path)
    {
        return BoundedInput.Read(path);
    }
}
