package rtnl

//lint:file-ignore U1000 the rtm* message types are used only by the linux build (conn_linux.go, events_linux.go)

// Numeric values from linux/rtnetlink.h, linux/fib_rules.h and
// linux/if_link.h. They are repeated here, rather than taken from
// golang.org/x/sys/unix, so the codec builds and is tested on any platform.
const (
	afInet  = 2
	afInet6 = 10

	rtmNewLink  = 16
	rtmDelLink  = 17
	rtmGetLink  = 18
	rtmNewAddr  = 20
	rtmDelAddr  = 21
	rtmGetAddr  = 22
	rtmNewRoute = 24
	rtmDelRoute = 25
	rtmGetRoute = 26
	rtmNewRule  = 32
	rtmDelRule  = 33
	rtmGetRule  = 34

	// fib_rule_hdr.action
	FRActToTbl       = 1
	FRActGoto        = 2
	FRActNop         = 3
	FRActBlackhole   = 6
	FRActUnreachable = 7
	FRActProhibit    = 8

	// fib_rule_hdr.flags
	FIBRulePermanent   = 0x1
	FIBRuleInvert      = 0x2
	FIBRuleUnresolved  = 0x4
	FIBRuleIifDetached = 0x8
	FIBRuleOifDetached = 0x10
	FIBRuleFindSaddr   = 0x10000

	fraDst            = 1
	fraSrc            = 2
	fraIifname        = 3
	fraGoto           = 4
	fraPriority       = 6
	fraFwmark         = 10
	fraSuppressIfgrp  = 13
	fraSuppressPrefix = 14
	fraTable          = 15
	fraFwmask         = 16
	fraOifname        = 17
	fraPad            = 18
	fraL3mdev         = 19
	fraProtocol       = 21
	fraIPProto        = 22

	// Route types and attributes.
	RTNUnicast     = 1
	RTNLocal       = 2
	RTNBroadcast   = 3
	RTNAnycast     = 4
	RTNMulticast   = 5
	RTNBlackhole   = 6
	RTNUnreachable = 7
	RTNProhibit    = 8
	RTNThrow       = 9
	RTNNAT         = 10

	RTProtoBoot = 3

	RTScopeUniverse = 0
	RTScopeLink     = 253
	RTScopeHost     = 254

	// rtm_flags / rtnh flags
	RTNHFDead       = 0x1
	RTNHFOnlink     = 0x4
	RTNHFLinkdown   = 0x10
	RTNHFUnresolved = 0x20

	rtaDst       = 1
	rtaSrc       = 2
	rtaIif       = 3
	rtaOif       = 4
	rtaGateway   = 5
	rtaPriority  = 6
	rtaPrefsrc   = 7
	rtaMetrics   = 8
	rtaMultipath = 9
	rtaTable     = 15
	rtaVia       = 18
	rtaEncapType = 21
	rtaEncap     = 22
	rtaPref      = 20
	rtaNHID      = 30

	// Tables.
	TableMain    = 254
	TableLocal   = 255
	TableDefault = 253
	tableCompat  = 252

	// Links.
	IFFUp      = 0x1
	IFFLowerUp = 0x10000

	iflaIfname    = 3
	iflaMTU       = 4
	iflaLinkinfo  = 18
	iflaOperstate = 16
	iflaInfoKind  = 1

	ifaAddress = 1
	ifaLocal   = 2
	ifaLabel   = 3
	ifaFlags   = 8

	nlaFNested       = 0x8000
	nlaFNetByteorder = 0x4000
	nlaTypeMask      = 0x3fff
)
