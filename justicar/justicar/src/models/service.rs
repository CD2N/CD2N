use serde::{Deserialize, Serialize};

#[derive(Clone, Serialize, Deserialize)]
pub struct SupplierDataAuditRequest {
    pub cid: String,
    pub user_acc: String,
    pub key: Vec<u8>,
    pub nonce: Vec<u8>,
    pub supplier_acc: String,
    pub data: Vec<u8>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct SupplierDataAuditResponse {
    pub msg: String,
    pub data: Vec<u8>,
}
