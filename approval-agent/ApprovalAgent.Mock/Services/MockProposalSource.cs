using ApprovalAgent.Mock.Models;

namespace ApprovalAgent.Mock.Services;

public sealed class MockProposalSource : IProposalSource
{
    public ApprovalProposal GetProposal()
    {
        return new ApprovalProposal(
            Provider: "Example API Provider",
            Model: "example-model",
            Destination: "https://api.example.invalid/v1/analyze",
            Task:
                "MOCK TASK — no provider will receive this text.\n\n" +
                "Review this synthetic proposal and identify unclear assumptions. " +
                "This multi-line sample is local demonstration content only.",
            ExpiresAtUtc: DateTimeOffset.UtcNow.AddMinutes(10));
    }
}
