use serde::{Deserialize, Serialize};
use crate::infrastructure::database::models::TargetGroup;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TargetGroupWithTargets {
    pub group: TargetGroup,
    pub targets: Vec<crate::infrastructure::database::models::Target>,
}
