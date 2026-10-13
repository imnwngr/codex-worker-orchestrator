using ApprovalAgent.Mock.Models;

namespace ApprovalAgent.Mock.Services;

public interface IProposalSource
{
    ApprovalProposal GetProposal();
}
