using System.Collections.ObjectModel;

namespace ApprovalAgent.Mock.Models;

public sealed record OfflineReviewTarget(string Id, string ProviderId, string ModelId, string Destination,
    string Task, string TaskSha256, string WireJson, long EffectiveTimeoutSeconds, long AdapterTimeoutSeconds, string RequestedEffort);

public sealed class OfflineReviewContext
{
    internal OfflineReviewContext(string requestId, string batchId, string sessionId, string contextSha256,
        string configurationFingerprint, string batchSha256, long createdAt, long expiresAt, OfflineReviewTarget[] targets)
    {
        RequestId = requestId; BatchId = batchId; SessionId = sessionId; ContextSha256 = contextSha256;
        ConfigurationFingerprint = configurationFingerprint; BatchSha256 = batchSha256;
        CreatedAt = createdAt; ExpiresAt = expiresAt; Targets = System.Array.AsReadOnly(targets);
    }
    public string RequestId { get; }
    public string BatchId { get; }
    public string SessionId { get; }
    public string ContextSha256 { get; }
    public string ConfigurationFingerprint { get; }
    public string BatchSha256 { get; }
    public long CreatedAt { get; }
    public long ExpiresAt { get; }
    public ReadOnlyCollection<OfflineReviewTarget> Targets { get; }
    public bool Authorized => false;
    public string ProductionAuthorization => "DEFAULT_DENY";
    public string IdentityStatus => "UNESTABLISHED";
}
