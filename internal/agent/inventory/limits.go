package inventory

// Entry-count limits per list.
const (
	maxPackages     = 30000
	maxUnits        = 4096
	maxPorts        = 2048
	maxUsers        = 4096
	maxGroups       = 4096
	maxGroupMembers = 256
	maxSudoRules    = 512
	maxTasks        = 1024
	maxTimers       = 512
	maxContainers   = 1024
	maxSSHKeys      = 32
	maxCerts        = 256
	maxCertFiles    = 1024
	maxCertDepth    = 4
	maxCertsPerFile = 16
	maxInterfaces   = 256
	maxAddrs        = 64
	maxRoutes       = 512
	maxDNS          = 16
	maxBlockDevices = 512
	maxFilesystems  = 256
	maxCronFiles    = 256
	maxDNSNames     = 64
	maxFDScanPIDs   = 4096
	maxFDsPerPID    = 4096
)

// String length limits (bytes).
const (
	maxShort = 64
	maxName  = 256
	maxText  = 512
	maxPath  = 1024
)

// File size limits (bytes).
const (
	maxSmallFile    = 64 << 10
	maxConfigFile   = 1 << 20
	maxCertFileSize = 256 << 10
	maxDpkgStatus   = 64 << 20
	maxWtmpTail     = 8 << 20
)

// Encoded-size budgets per section (bytes). Their sum (~3 MiB) keeps a full
// report below the 4 MiB gRPC default; maxSectionBytes is a final guard.
const (
	budgetPackages   = 1792 << 10
	budgetServices   = 320 << 10
	budgetUsers      = 160 << 10
	budgetGroups     = 64 << 10
	budgetSudo       = 32 << 10
	budgetPorts      = 96 << 10
	budgetScheduled  = 96 << 10
	budgetContainers = 96 << 10
	budgetCerts      = 96 << 10
	budgetInterfaces = 48 << 10
	budgetRoutes     = 48 << 10
	budgetBlockDevs  = 48 << 10
	budgetFS         = 48 << 10
	maxSectionBytes  = 2 << 20
)
