using System.ComponentModel;
using System.Globalization;
using System.Runtime.CompilerServices;
using ApprovalAgent.Mock.Models;

namespace ApprovalAgent.Mock.ViewModels;

public enum MockApprovalState
{
    Pending,
    ApprovedMock,
    Rejected,
    Expired
}

public sealed class ApprovalViewModel : INotifyPropertyChanged
{
    private readonly Func<DateTimeOffset> _utcNow;
    private MockApprovalState _state = MockApprovalState.Pending;
    private string _statusMessage = "Review the complete proposal before choosing.";

    public ApprovalViewModel(
        ApprovalProposal proposal,
        Func<DateTimeOffset>? utcNow = null)
    {
        Proposal = proposal ?? throw new ArgumentNullException(nameof(proposal));
        _utcNow = utcNow ?? (() => DateTimeOffset.UtcNow);
        RefreshExpiry();
    }

    public event PropertyChangedEventHandler? PropertyChanged;

    public ApprovalProposal Proposal { get; }

    public string ExternalTransmissionWarning =>
        "In a future connected system, approving would send the complete task " +
        "to the external provider destination shown here. This mock prototype " +
        "sends nothing and does not contact any provider.";

    public string ExpiresAtDisplay =>
        Proposal.ExpiresAtUtc.ToUniversalTime()
            .ToString("yyyy-MM-dd HH:mm:ss 'UTC'", CultureInfo.InvariantCulture);

    public MockApprovalState State
    {
        get => _state;
        private set
        {
            if (_state == value) return;
            _state = value;
            OnPropertyChanged();
            OnPropertyChanged(nameof(CanApprove));
            OnPropertyChanged(nameof(CanReject));
        }
    }

    public string StatusMessage
    {
        get => _statusMessage;
        private set
        {
            if (_statusMessage == value) return;
            _statusMessage = value;
            OnPropertyChanged();
        }
    }

    public bool CanApprove => State == MockApprovalState.Pending;
    public bool CanReject => State == MockApprovalState.Pending;

    public void RefreshExpiry()
    {
        if (State != MockApprovalState.Pending ||
            _utcNow().ToUniversalTime() < Proposal.ExpiresAtUtc.ToUniversalTime())
        {
            return;
        }

        State = MockApprovalState.Expired;
        StatusMessage = "Expired. This mock proposal can no longer be approved.";
    }

    public bool ApproveMock()
    {
        RefreshExpiry();
        if (!CanApprove) return false;

        State = MockApprovalState.ApprovedMock;
        StatusMessage = "Mock approval recorded in memory only. Nothing was sent.";
        return true;
    }

    public bool Reject()
    {
        RefreshExpiry();
        if (!CanReject) return false;

        State = MockApprovalState.Rejected;
        StatusMessage = "Mock proposal rejected in memory only. Nothing was sent.";
        return true;
    }

    private void OnPropertyChanged([CallerMemberName] string? propertyName = null)
    {
        PropertyChanged?.Invoke(
            this,
            new PropertyChangedEventArgs(propertyName));
    }
}
