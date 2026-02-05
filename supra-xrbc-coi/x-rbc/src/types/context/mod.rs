use crate::tasks::codec::SupraDeliveryErasureCodecSchema;
use crate::tasks::config::DisseminationRule;
use crate::types::helpers::assignment_extractor::AssignmentExtractor;
use crate::types::messages::ResponseTypeIfc;
use crate::types::payload_state::PayloadFlags;
use ::network::topology::ChainTopology;
use crypto::Authenticator;
use primitives::types::HeaderIfc;
use primitives::Protocol;
use std::marker::PhantomData;
use storage::storage_client::StorageClient;

pub(crate) mod committee;
pub(crate) mod network;
pub(crate) mod sync;

pub(crate) trait ResourcesApi {
    fn storage_client(&self) -> &StorageClient;
    fn topology(&self) -> &ChainTopology;
    fn authenticator(&self) -> &Authenticator;
    ///
    /// Returns assignment extractor instance
    ///
    fn assignment_extractor(&self) -> AssignmentExtractor;
    /// Data dissemination rule in scope of the broadcaster clan
    fn dissemination_rule(&self) -> DisseminationRule;
}

///
/// Resources facilitating message processing logic
///
pub(crate) struct Resources {
    /// Chain topology to assist incoming data verification and outgoing data dissemination
    chain_topology: ChainTopology,
    /// Authenticator to assist incoming data and outgoing data authentication
    authenticator: Authenticator,
    /// Storage client to store the deliverable in the storage upon successful delivery
    storage_client: StorageClient,
    /// Data dissemination rule in scope of the broadcaster clan
    dissemination_rule: DisseminationRule,
}

impl Resources {
    pub(crate) fn new(
        chain_topology: ChainTopology,
        authenticator: Authenticator,
        storage_client: StorageClient,
        dissemination_rule: DisseminationRule,
    ) -> Self {
        Resources {
            chain_topology,
            authenticator,
            storage_client,
            dissemination_rule,
        }
    }

    pub(crate) fn split(self) -> (ChainTopology, Authenticator, StorageClient) {
        (self.chain_topology, self.authenticator, self.storage_client)
    }
}

impl ResourcesApi for Resources {
    ///
    /// Returns reference to storage client
    ///
    fn storage_client(&self) -> &StorageClient {
        &self.storage_client
    }

    ///
    /// Returns topology of the chain
    ///
    fn topology(&self) -> &ChainTopology {
        &self.chain_topology
    }

    ///
    /// Returns authenticator instance providing cryptography apis
    ///
    fn authenticator(&self) -> &Authenticator {
        &self.authenticator
    }

    ///
    /// Returns assignment extractor instance
    ///
    fn assignment_extractor(&self) -> AssignmentExtractor {
        AssignmentExtractor::new(self.topology(), Protocol::XRBC, &self.dissemination_rule)
    }

    ///
    /// Returns assignment extractor instance
    ///
    fn dissemination_rule(&self) -> DisseminationRule {
        self.dissemination_rule
    }
}

///
/// Schema defining state machine context properties
///
pub(crate) trait FSMContextSchema {
    /// Data structure holding current state of the payload
    type PayloadStateType: HeaderIfc + PayloadFlags;
    /// Response type of the state-machine
    type ResponseType: Default + ResponseTypeIfc;
    /// Delivery encoding schema used to encode deliverable
    type CodecSchema: SupraDeliveryErasureCodecSchema;
}

///
/// Data structure describing the context of the state machine
/// It hold payload current state, generated response and external APIs facilitate delivery process
///
pub(crate) struct FSMContext<Schema: FSMContextSchema> {
    data: Schema::PayloadStateType,
    response: Option<Schema::ResponseType>,
    api: Resources,
    _phantom_: PhantomData<Schema>,
}

impl<Schema: FSMContextSchema> FSMContext<Schema> {
    pub(crate) fn new(data: Schema::PayloadStateType, api: Resources) -> Self {
        Self {
            data,
            response: None,
            api,
            _phantom_: Default::default(),
        }
    }
}

///
/// Generic interface providing API to fetch FSM context properties
///
pub(crate) trait FSMContextOwner {
    type Schema: FSMContextSchema;

    fn context(&self) -> &FSMContext<Self::Schema>;

    fn context_mut(&mut self) -> &mut FSMContext<Self::Schema>;

    ///
    /// Returns chunked data index assigned to the current node by the broadcaster
    ///
    fn owned_chunk_data_index(&self) -> usize {
        let current_node = self.resources().topology().current_node();
        if self
            .resources()
            .topology()
            .is_clan_member(self.payload_state().origin())
            .unwrap()
        {
            return current_node.position();
        }
        self.assignment_extractor()
            .assigned_chunk_index(self.payload_state().origin())
            - self.topology().get_committee_size()
    }

    fn resources(&self) -> &Resources {
        &self.context().api
    }

    fn resource_mut(&mut self) -> &mut Resources {
        &mut self.context_mut().api
    }

    fn response(&self) -> &Option<<Self::Schema as FSMContextSchema>::ResponseType> {
        &self.context().response
    }

    fn response_mut(&mut self) -> &mut <Self::Schema as FSMContextSchema>::ResponseType {
        if self.context().response.is_none() {
            self.context_mut().response = Some(Default::default())
        }
        self.context_mut().response.as_mut().unwrap()
    }

    fn take_response(&mut self) -> Option<<Self::Schema as FSMContextSchema>::ResponseType> {
        self.context_mut().response.take()
    }

    fn payload_state(&self) -> &<Self::Schema as FSMContextSchema>::PayloadStateType {
        &self.context().data
    }

    fn payload_state_mut(&mut self) -> &mut <Self::Schema as FSMContextSchema>::PayloadStateType {
        &mut self.context_mut().data
    }
}

impl<T: ?Sized + FSMContextOwner> ResourcesApi for T {
    fn storage_client(&self) -> &StorageClient {
        self.resources().storage_client()
    }

    fn topology(&self) -> &ChainTopology {
        self.resources().topology()
    }

    fn authenticator(&self) -> &Authenticator {
        self.resources().authenticator()
    }

    fn assignment_extractor(&self) -> AssignmentExtractor {
        self.resources().assignment_extractor()
    }

    fn dissemination_rule(&self) -> DisseminationRule {
        self.resources().dissemination_rule()
    }
}

impl<SCM: FSMContextSchema> FSMContextOwner for FSMContext<SCM> {
    type Schema = SCM;

    fn context(&self) -> &FSMContext<Self::Schema> {
        self
    }

    fn context_mut(&mut self) -> &mut FSMContext<Self::Schema> {
        self
    }
}
