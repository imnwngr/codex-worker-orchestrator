using System.Security.Cryptography;
using System.Text;

namespace ApprovalAgent.Mock.Models;

public sealed record ApprovalProposal(
    string Provider,
    string Model,
    string Destination,
    string Task,
    DateTimeOffset ExpiresAtUtc)
{
    public string TaskSha256 =>
        Convert.ToHexString(
            SHA256.HashData(Encoding.UTF8.GetBytes(Task)))
        .ToLowerInvariant();
}
