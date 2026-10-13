using System.Security.Cryptography;
using System.Text;
using ApprovalAgent.Mock.Models;
using ApprovalAgent.Mock.Services;
using ApprovalAgent.Mock.ViewModels;

var tests = new (string Name, Action Run)[]
{
    ("preserves exact task text and calculates its UTF-8 SHA-256", ExactTextAndHash),
    ("allows mock approval before expiry and records no persistent result", ApproveBeforeExpiry),
    ("rejects mock approval at the expiry instant", CannotApproveAtExpiry),
    ("rejects mock approval after expiry", CannotApproveAfterExpiry),
    ("reject action changes only in-memory mock state", RejectIsLocalState),
    ("terminal states cannot be changed by later actions", TerminalStateIsStable),
    ("fixed proposal stays synthetic and cannot reach a live endpoint", SourceIsMockOnly),
    ("review model exposes a prominent complete-task warning", TransmissionWarning)
};

var failures = 0;
foreach (var (name, run) in tests)
{
    try
    {
        run();
        Console.WriteLine($"PASS {name}");
    }
    catch (Exception error)
    {
        failures++;
        Console.Error.WriteLine($"FAIL {name}: {error.Message}");
    }
}

Console.WriteLine($"{tests.Length - failures}/{tests.Length} mock tests passed.");
return failures == 0 ? 0 : 1;

static void ExactTextAndHash()
{
    const string task = "line one\r\nline two\n  trailing space ";
    var proposal = Proposal(task);
    var expected = Convert.ToHexString(
        SHA256.HashData(Encoding.UTF8.GetBytes(task))).ToLowerInvariant();

    Equal(task, proposal.Task, "Task text must be preserved byte-for-byte as a string.");
    Equal(expected, proposal.TaskSha256, "Hash must cover the exact UTF-8 task text.");
}

static void ApproveBeforeExpiry()
{
    var now = DateTimeOffset.Parse("2030-01-02T03:04:05Z");
    var viewModel = new ApprovalViewModel(Proposal("sample", now.AddSeconds(1)), () => now);

    True(viewModel.CanApprove, "Unexpired proposal should allow mock approval.");
    True(viewModel.ApproveMock(), "Mock approval should transition from Pending.");
    Equal(MockApprovalState.ApprovedMock, viewModel.State, "Expected mock-approved state.");
    True(!viewModel.CanApprove && !viewModel.CanReject,
        "Terminal state must disable both actions.");
    True(viewModel.StatusMessage.Contains("Nothing was sent.", StringComparison.Ordinal),
        "Status must confirm no transmission.");
}

static void CannotApproveAtExpiry()
{
    var now = DateTimeOffset.Parse("2030-01-02T03:04:05Z");
    var viewModel = new ApprovalViewModel(Proposal("sample", now), () => now);

    True(!viewModel.ApproveMock(), "Expiry instant is no longer valid.");
    Equal(MockApprovalState.Expired, viewModel.State, "Expected expired state.");
}

static void CannotApproveAfterExpiry()
{
    var now = DateTimeOffset.Parse("2030-01-02T03:04:05Z");
    var viewModel = new ApprovalViewModel(Proposal("sample", now.AddTicks(-1)), () => now);

    True(!viewModel.CanApprove, "Expired proposal should disable approval.");
    True(!viewModel.ApproveMock(), "Expired proposal must not transition to approved.");
    Equal(MockApprovalState.Expired, viewModel.State, "Expected expired state.");
}

static void RejectIsLocalState()
{
    var now = DateTimeOffset.Parse("2030-01-02T03:04:05Z");
    var viewModel = new ApprovalViewModel(Proposal("sample", now.AddMinutes(1)), () => now);

    True(viewModel.Reject(), "Pending proposal should be rejectable.");
    Equal(MockApprovalState.Rejected, viewModel.State, "Expected rejected state.");
    True(viewModel.StatusMessage.Contains("Nothing was sent.", StringComparison.Ordinal),
        "Reject must not send data.");
}

static void TerminalStateIsStable()
{
    var now = DateTimeOffset.Parse("2030-01-02T03:04:05Z");
    var viewModel = new ApprovalViewModel(Proposal("sample", now.AddMinutes(1)), () => now);

    True(viewModel.Reject(), "Initial reject should succeed.");
    True(!viewModel.ApproveMock(), "Rejected proposal cannot later be approved.");
    True(!viewModel.Reject(), "A second reject has no effect.");
    Equal(MockApprovalState.Rejected, viewModel.State, "Rejected state must remain stable.");
}

static void SourceIsMockOnly()
{
    var proposal = new MockProposalSource().GetProposal();
    var destination = new Uri(proposal.Destination);
    True(destination.Scheme == Uri.UriSchemeHttps, "Mock destination should use HTTPS syntax.");
    True(destination.Host.EndsWith(".invalid", StringComparison.OrdinalIgnoreCase),
        "Mock proposal must not use a real external API destination.");
    True(proposal.Task.Contains("MOCK TASK", StringComparison.Ordinal),
        "Synthetic task should be clearly labeled.");
    True(proposal.TaskSha256.Length == 64, "SHA-256 should be 64 hex characters.");
}

static void TransmissionWarning()
{
    var now = DateTimeOffset.Parse("2030-01-02T03:04:05Z");
    var viewModel = new ApprovalViewModel(Proposal("sample", now.AddMinutes(1)), () => now);
    True(viewModel.ExternalTransmissionWarning.Contains("complete task", StringComparison.Ordinal),
        "Warning must describe sending the complete task.");
    True(viewModel.ExternalTransmissionWarning.Contains("external provider destination", StringComparison.Ordinal),
        "Warning must mention the external destination.");
    True(viewModel.ExternalTransmissionWarning.Contains("sends nothing", StringComparison.Ordinal),
        "Warning must clearly distinguish the mock from real dispatch.");
}

static ApprovalProposal Proposal(
    string task,
    DateTimeOffset? expiresAt = null) =>
    new(
        Provider: "Mock Provider",
        Model: "mock-model",
        Destination: "https://api.example.invalid/v1/analyze",
        Task: task,
        ExpiresAtUtc: expiresAt ?? DateTimeOffset.Parse("2030-01-02T03:05:05Z"));

static void Equal<T>(T expected, T actual, string message)
{
    if (!EqualityComparer<T>.Default.Equals(expected, actual))
    {
        throw new InvalidOperationException(
            $"{message} Expected '{expected}', got '{actual}'.");
    }
}

static void True(bool condition, string message)
{
    if (!condition) throw new InvalidOperationException(message);
}
