import type { components } from './schema';

type S = components['schemas'];

export type SystemInfo = S['SystemInfo'];
export type Settings = S['Settings'];
export type NotificationSettings = S['NotificationSettings'];
export type WebhookTarget = S['WebhookTarget'];
export type ShellSettings = S['ShellSettings'];
export type ShellIdentityMode = S['ShellIdentityMode'];

export type LoginResult = S['LoginResult'];
export type SessionState = S['SessionState'];
export type SessionInfo = S['SessionInfo'];
export type TotpEnrollment = S['TotpEnrollment'];
export type WebauthnCredential = S['WebauthnCredential'];

export type User = S['User'];
export type UserCreate = S['UserCreate'];
export type UserUpdate = S['UserUpdate'];
export type Role = S['Role'];
export type RoleBinding = S['RoleBinding'];
export type RoleBindingInput = S['RoleBindingInput'];

export type HostGroup = S['HostGroup'];
export type HostGroupInput = S['HostGroupInput'];
export type GroupShellSettings = S['GroupShellSettings'];

export type HostStatus = S['HostStatus'];
export type Host = S['Host'];
export type HostUpdate = S['HostUpdate'];
export type PolicySummary = S['PolicySummary'];
export type Inventory = S['Inventory'];
export type InventorySection = S['InventorySection'];
export type Package = S['Package'];
export type HostUpdates = S['HostUpdates'];
export type PendingUpdate = S['PendingUpdate'];
export type HostUpdatesSummary = S['HostUpdatesSummary'];
export type ProcessSnapshot = S['ProcessSnapshot'];
export type ProcessInfo = S['ProcessSnapshot']['processes'][number];
export type MetricsPanel = S['MetricsPanel'];
export type MetricsResponse = S['MetricsResponse'];
export type CheckResult = S['CheckResult'];
export type SecuritySummary = S['SecuritySummary'];

export type ShellSessionCreate = S['ShellSessionCreate'];
export type ShellSession = S['ShellSession'];

export type EnrollmentToken = S['EnrollmentToken'];
export type EnrollmentTokenCreate = S['EnrollmentTokenCreate'];
export type EnrollmentTokenCreated = S['EnrollmentTokenCreated'];

export type JobType = S['JobType'];
export type JobCreate = S['JobCreate'];
export type JobParams = S['JobParams'];
export type JobTargets = S['JobTargets'];
export type JobStatus = S['JobStatus'];
export type Job = S['Job'];
export type JobTargetStatus = S['JobTargetStatus'];
export type JobTarget = S['JobTarget'];
export type JobOutputChunk = S['JobOutputChunk'];

export type AuditEntry = S['AuditEntry'];
export type AuditVerifyResult = S['AuditVerifyResult'];
export type Alert = S['Alert'];
export type Dashboard = S['Dashboard'];
export type ApiEvent = S['Event'];
