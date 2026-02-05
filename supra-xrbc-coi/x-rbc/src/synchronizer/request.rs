use primitives::types::QuorumCertificate;
use primitives::types::{Header, HeaderIfc};
use primitives::NotificationSender;

pub(crate) type SyncResponse = Result<(), String>;
///
/// Internal Sync request message sent from Synchronizer to SupraDelivery
///
#[derive(Debug)]
pub struct InternalSyncRequest {
    header: Header,
    qc: QuorumCertificate,
    feedback: NotificationSender<SyncResponse>,
}

impl HeaderIfc for InternalSyncRequest {
    fn header(&self) -> &Header {
        &self.header
    }
}

impl InternalSyncRequest {
    pub(crate) fn new(
        header: Header,
        qc: QuorumCertificate,
        feedback: NotificationSender<SyncResponse>,
    ) -> Self {
        Self {
            header,
            qc,
            feedback,
        }
    }

    pub(crate) fn get_qc(&self) -> QuorumCertificate {
        self.qc.clone()
    }

    pub(crate) fn split(self) -> (Header, QuorumCertificate, NotificationSender<SyncResponse>) {
        (self.header, self.qc, self.feedback)
    }
}
