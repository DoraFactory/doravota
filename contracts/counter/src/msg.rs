use cosmwasm_schema::{cw_serde, QueryResponses};

#[cw_serde]
pub struct InstantiateMsg {
    pub initial_count: i32,
}

#[cw_serde]
pub enum ExecuteMsg {
    Increment { amount: i32 },
    Decrement {},
    Reset { count: i32 },
    // add whitelist management functionality
    AddToWhitelist { address: String },
    RemoveFromWhitelist { address: String },
}

#[cw_serde]
#[derive(QueryResponses)]
pub enum QueryMsg {
    // GetCount returns the current count as a json-encoded number
    #[returns(GetCountResponse)]
    GetCount {},
    // CheckPolicy check if the user is eligible for sponsorship based on message type
    #[returns(CheckPolicyResponse)]
    CheckPolicy { 
        sender: String,
        msg_data: String,
    },
    // query whitelist status
    #[returns(WhitelistResponse)]
    IsWhitelisted { address: String },
}

// We define a custom struct for each query response
#[cw_serde]
pub struct GetCountResponse {
    pub count: i32,
}

#[cw_serde]
pub struct CheckPolicyResponse {
    pub eligible: bool,
    pub reason: Option<String>,
}

#[cw_serde]
pub struct WhitelistResponse {
    pub is_whitelisted: bool,
}

#[cw_serde]
pub struct MigrateMsg {}
