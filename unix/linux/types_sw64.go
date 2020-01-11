// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// +build ignore

/*
Input to cgo -godefs.  See README.md
*/

// +godefs map struct_in_addr [4]byte /* in_addr */
// +godefs map struct_in6_addr [16]byte /* in6_addr */

package unix

/*
#define _LARGEFILE_SOURCE
#define _LARGEFILE64_SOURCE
#define _FILE_OFFSET_BITS 64
#define _GNU_SOURCE

#include <dirent.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <sys/epoll.h>
#include <sys/inotify.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/mount.h>
#include <sys/param.h>
#include <sys/ptrace.h>
#include <sys/resource.h>
#include <sys/select.h>
#include <sys/signal.h>
#include <sys/statfs.h>
#include <sys/statvfs.h>
#include <sys/sysinfo.h>
#include <sys/time.h>
#include <sys/times.h>
#include <sys/timex.h>
#include <sys/un.h>
#include <sys/user.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include <linux/filter.h>
#include <linux/icmpv6.h>
#include <linux/keyctl.h>
#include <linux/netfilter/nf_tables.h>
#include <linux/netfilter/nfnetlink.h>
#include <linux/netfilter.h>
#include <linux/netlink.h>
#include <linux/perf_event.h>
#include <linux/rtnetlink.h>
#include <linux/stat.h>
#if defined(__sparc__)
// On sparc{,64}, the kernel defines struct termios2 itself which clashes with the
// definition in glibc. Duplicate the kernel version here.
#if defined(__arch64__)
typedef unsigned int tcflag_t;
#else
typedef unsigned long tcflag_t;
#endif

struct termios2 {
	tcflag_t c_iflag;
	tcflag_t c_oflag;
	tcflag_t c_cflag;
	tcflag_t c_lflag;
	unsigned char c_line;
	unsigned char c_cc[19];
	unsigned int c_ispeed;
	unsigned int c_ospeed;
};
#else
#include <asm/termbits.h>
#endif
#include <asm/ptrace.h>
#include <time.h>
#include <unistd.h>
#include <utime.h>
#include <linux/can.h>
#include <linux/if_alg.h>
#include <linux/if_packet.h>
#include <linux/fs.h>
#include <linux/vm_sockets.h>
#include <linux/random.h>
#include <linux/taskstats.h>
#include <linux/cgroupstats.h>
#include <linux/genetlink.h>
#include <linux/socket.h>
#include <linux/hdreg.h>
#include <linux/rtc.h>
#include <linux/blkpg.h>
#include <linux/net_namespace.h>
#include <linux/net_tstamp.h>

// On mips64, the glibc stat and kernel stat do not agree
#if (defined(__mips__) && _MIPS_SIM == _MIPS_SIM_ABI64)

// Use the stat defined by the kernel with a few modifications. These are:
//	* The time fields (like st_atime and st_atimensec) use the timespec
//	  struct (like st_atim) for consistency with the glibc fields.
//	* The padding fields get different names to not break compatibility.
//	* st_blocks is signed, again for compatibility.
struct stat {
	unsigned int		st_dev;
	unsigned int		st_pad1[3]; // Reserved for st_dev expansion

	unsigned long		st_ino;

	mode_t			st_mode;
	__u32			st_nlink;

	uid_t			st_uid;
	gid_t			st_gid;

	unsigned int		st_rdev;
	unsigned int		st_pad2[3]; // Reserved for st_rdev expansion

	off_t			st_size;

	// These are declared as separate fields in the kernel. Here we use
	// the timespec struct for consistency with the other stat structs.
	struct timespec		st_atim;
	struct timespec		st_mtim;
	struct timespec		st_ctim;

	unsigned int		st_blksize;
	unsigned int		st_pad4;

	long			st_blocks;
};

// These are needed because we do not include fcntl.h or sys/types.h
#include <linux/fcntl.h>
#include <linux/fadvise.h>

#else

// Use the stat defined by glibc
#include <fcntl.h>
#include <sys/types.h>

#endif

// These are defined in linux/fcntl.h, but including it globally causes
// conflicts with fcntl.h
#ifndef AT_STATX_SYNC_TYPE
# define AT_STATX_SYNC_TYPE	0x6000	// Type of synchronisation required from statx()
#endif
#ifndef AT_STATX_SYNC_AS_STAT
# define AT_STATX_SYNC_AS_STAT	0x0000	// - Do whatever stat() does
#endif
#ifndef AT_STATX_FORCE_SYNC
# define AT_STATX_FORCE_SYNC	0x2000	// - Force the attributes to be sync'd with the server
#endif
#ifndef AT_STATX_DONT_SYNC
# define AT_STATX_DONT_SYNC	0x4000	// - Don't sync attributes with the server
#endif

#ifndef AT_EACCESS
# define AT_EACCESS		0x200	// Test access permitted for effective IDs, not real IDs.
#endif

#ifdef TCSETS2
// On systems that have "struct termios2" use this as type Termios.
typedef struct termios2 termios_t;
#else
typedef struct termios termios_t;
#endif

enum {
	sizeofPtr = sizeof(void*),
};

union sockaddr_all {
	struct sockaddr s1;	// this one gets used for fields
	struct sockaddr_in s2;	// these pad it out
	struct sockaddr_in6 s3;
	struct sockaddr_un s4;
	struct sockaddr_ll s5;
	struct sockaddr_nl s6;
};

struct sockaddr_any {
	struct sockaddr addr;
	char pad[sizeof(union sockaddr_all) - sizeof(struct sockaddr)];
};

// copied from /usr/include/bluetooth/hci.h
struct sockaddr_hci {
        sa_family_t     hci_family;
        unsigned short  hci_dev;
        unsigned short  hci_channel;
};

// copied from /usr/include/bluetooth/bluetooth.h
#define BDADDR_BREDR           0x00
#define BDADDR_LE_PUBLIC       0x01
#define BDADDR_LE_RANDOM       0x02

// copied from /usr/include/bluetooth/l2cap.h
struct sockaddr_l2 {
	sa_family_t	l2_family;
	unsigned short	l2_psm;
	uint8_t		l2_bdaddr[6];
	unsigned short	l2_cid;
	uint8_t		l2_bdaddr_type;
};

// copied from /usr/include/net/bluetooth/rfcomm.h
struct sockaddr_rc {
	sa_family_t rc_family;
	uint8_t     rc_bdaddr[6];
	uint8_t     rc_channel;
};

// copied from /usr/include/linux/un.h
struct my_sockaddr_un {
	sa_family_t sun_family;
#if defined(__ARM_EABI__) || defined(__powerpc64__)
	// on ARM char is by default unsigned
	signed char sun_path[108];
#else
	char sun_path[108];
#endif
};

#ifdef __ARM_EABI__
typedef struct user_regs PtraceRegs;
#elif defined(__aarch64__)
typedef struct user_pt_regs PtraceRegs;
#elif defined(__mips__) || defined(__powerpc64__)
typedef struct pt_regs PtraceRegs;
#elif defined(__s390x__)
typedef struct _user_regs_struct PtraceRegs;
#elif defined(__sparc__)
#include <asm/ptrace.h>
typedef struct pt_regs PtraceRegs;
#else
typedef struct user_regs_struct PtraceRegs;
#endif

#if defined(__s390x__)
typedef struct _user_psw_struct ptracePsw;
typedef struct _user_fpregs_struct ptraceFpregs;
typedef struct _user_per_struct ptracePer;
#else
typedef struct {} ptracePsw;
typedef struct {} ptraceFpregs;
typedef struct {} ptracePer;
#endif

// The real epoll_event is a union, and godefs doesn't handle it well.
struct my_epoll_event {
	uint32_t events;
	int32_t _padFd;
	int32_t fd;
	int32_t pad;
};

// Copied from <linux/perf_event.h> with the following modifications:
// 1) bit field after read_format redeclared as '__u64 bits' to make it
//    accessible from Go
// 2) collapsed the unions, to avoid confusing godoc for the generated output
//    (e.g. having to use BpAddr as an extension of Config)
struct perf_event_attr_go {
	__u32 type;

	__u32 size;
	__u64 config;

	// union {
	//   __u64 sample_period;
	//   __u64 sample_freq;
	// };
	__u64 sample;

	__u64 sample_type;
	__u64 read_format;

	// Replaces the bit field. Flags are defined as constants.
	__u64 bits;

	// union {
	//   __u32 wakeup_events;
	//   __u32 wakeup_watermark;
	// };
	__u32 wakeup;

	__u32 bp_type;

	// union {
	//   __u64 bp_addr;
	//   __u64 config1;
	// };
	__u64 ext1;

	// union {
	//   __u64 bp_len;
	//   __u64 config2;
	// };
	__u64 ext2;

	__u64 branch_sample_type;

	__u64 sample_regs_user;

	__u32 sample_stack_user;

	__s32 clockid;
	__u64 sample_regs_intr;
	__u32 aux_watermark;
	__u32 __reserved_2;
};

// ustat is deprecated and glibc 2.28 removed ustat.h. Provide the type here for
// backwards compatibility. Copied from /usr/include/bits/ustat.h
struct ustat {
	__daddr_t f_tfree;
	__ino_t f_tinode;
	char f_fname[6];
	char f_fpack[6];
};

// my_blkpg_partition is blkpg_partition with unsigned devname & volname.
struct my_blkpg_partition {
	long long start;
	long long length;
	int pno;
	unsigned char devname[BLKPG_DEVNAMELTH];
	unsigned char volname[BLKPG_VOLNAMELTH];
};

*/
import "C"

// Machine characteristics

const (
	SizeofPtr      = C.sizeofPtr
	SizeofShort    = C.sizeof_short
	SizeofInt      = C.sizeof_int
	SizeofLong     = C.sizeof_long
	SizeofLongLong = C.sizeof_longlong
	PathMax        = C.PATH_MAX
)

// Basic types

type (
	_C_short     C.short
	_C_int       C.int
	_C_long      C.long
	_C_long_long C.longlong
)

// Time

type Timespec C.struct_timespec

type Timeval C.struct_timeval

type Timex C.struct_timex

type Time_t C.time_t

type Tms C.struct_tms

type Utimbuf C.struct_utimbuf

// Processes

type Rusage C.struct_rusage

type Rlimit C.struct_rlimit

type _Gid_t C.gid_t

// Files

type Stat_t C.struct_stat

//type StatxTimestamp C.struct_statx_timestamp
//type Statx_t C.struct_statx

type Dirent C.struct_dirent

type Fsid C.fsid_t

type Flock_t C.struct_flock

// Filesystem Encryption

type FscryptPolicy C.struct_fscrypt_policy

type FscryptKey C.struct_fscrypt_key

// Structure for Keyctl

type KeyctlDHParams C.struct_keyctl_dh_params

// Advice to Fadvise

const (
	FADV_NORMAL     = C.POSIX_FADV_NORMAL
	FADV_RANDOM     = C.POSIX_FADV_RANDOM
	FADV_SEQUENTIAL = C.POSIX_FADV_SEQUENTIAL
	FADV_WILLNEED   = C.POSIX_FADV_WILLNEED
	FADV_DONTNEED   = C.POSIX_FADV_DONTNEED
	FADV_NOREUSE    = C.POSIX_FADV_NOREUSE
)

// Sockets

type RawSockaddrInet4 C.struct_sockaddr_in

type RawSockaddrInet6 C.struct_sockaddr_in6

type RawSockaddrUnix C.struct_my_sockaddr_un

type RawSockaddrLinklayer C.struct_sockaddr_ll

type RawSockaddrNetlink C.struct_sockaddr_nl

type RawSockaddrHCI C.struct_sockaddr_hci

type RawSockaddrL2 C.struct_sockaddr_l2

type RawSockaddrRFCOMM C.struct_sockaddr_rc

type RawSockaddrCAN C.struct_sockaddr_can

type RawSockaddrALG C.struct_sockaddr_alg

type RawSockaddrVM C.struct_sockaddr_vm

type RawSockaddr C.struct_sockaddr

type RawSockaddrAny C.struct_sockaddr_any

type _Socklen C.socklen_t

type Linger C.struct_linger

type Iovec C.struct_iovec

type IPMreq C.struct_ip_mreq

type IPMreqn C.struct_ip_mreqn

type IPv6Mreq C.struct_ipv6_mreq

type PacketMreq C.struct_packet_mreq

type Msghdr C.struct_msghdr

type Cmsghdr C.struct_cmsghdr

type Inet4Pktinfo C.struct_in_pktinfo

type Inet6Pktinfo C.struct_in6_pktinfo

type IPv6MTUInfo C.struct_ip6_mtuinfo

type ICMPv6Filter C.struct_icmp6_filter

type Ucred C.struct_ucred

type TCPInfo C.struct_tcp_info

const (
	SizeofSockaddrInet4     = C.sizeof_struct_sockaddr_in
	SizeofSockaddrInet6     = C.sizeof_struct_sockaddr_in6
	SizeofSockaddrAny       = C.sizeof_struct_sockaddr_any
	SizeofSockaddrUnix      = C.sizeof_struct_sockaddr_un
	SizeofSockaddrLinklayer = C.sizeof_struct_sockaddr_ll
	SizeofSockaddrNetlink   = C.sizeof_struct_sockaddr_nl
	SizeofSockaddrHCI       = C.sizeof_struct_sockaddr_hci
	SizeofSockaddrL2        = C.sizeof_struct_sockaddr_l2
	SizeofSockaddrRFCOMM    = C.sizeof_struct_sockaddr_rc
	SizeofSockaddrCAN       = C.sizeof_struct_sockaddr_can
	SizeofSockaddrALG       = C.sizeof_struct_sockaddr_alg
	SizeofSockaddrVM        = C.sizeof_struct_sockaddr_vm
	SizeofLinger            = C.sizeof_struct_linger
	SizeofIovec             = C.sizeof_struct_iovec
	SizeofIPMreq            = C.sizeof_struct_ip_mreq
	SizeofIPMreqn           = C.sizeof_struct_ip_mreqn
	SizeofIPv6Mreq          = C.sizeof_struct_ipv6_mreq
	SizeofPacketMreq        = C.sizeof_struct_packet_mreq
	SizeofMsghdr            = C.sizeof_struct_msghdr
	SizeofCmsghdr           = C.sizeof_struct_cmsghdr
	SizeofInet4Pktinfo      = C.sizeof_struct_in_pktinfo
	SizeofInet6Pktinfo      = C.sizeof_struct_in6_pktinfo
	SizeofIPv6MTUInfo       = C.sizeof_struct_ip6_mtuinfo
	SizeofICMPv6Filter      = C.sizeof_struct_icmp6_filter
	SizeofUcred             = C.sizeof_struct_ucred
	SizeofTCPInfo           = C.sizeof_struct_tcp_info
)

const (
	IFA_UNSPEC           = C.IFA_UNSPEC
	IFA_ADDRESS          = C.IFA_ADDRESS
	IFA_LOCAL            = C.IFA_LOCAL
	IFA_LABEL            = C.IFA_LABEL
	IFA_BROADCAST        = C.IFA_BROADCAST
	IFA_ANYCAST          = C.IFA_ANYCAST
	IFA_CACHEINFO        = C.IFA_CACHEINFO
	IFA_MULTICAST        = C.IFA_MULTICAST
	IFLA_UNSPEC          = C.IFLA_UNSPEC
	IFLA_ADDRESS         = C.IFLA_ADDRESS
	IFLA_BROADCAST       = C.IFLA_BROADCAST
	IFLA_IFNAME          = C.IFLA_IFNAME
	IFLA_INFO_KIND       = C.IFLA_INFO_KIND
	IFLA_MTU             = C.IFLA_MTU
	IFLA_LINK            = C.IFLA_LINK
	IFLA_QDISC           = C.IFLA_QDISC
	IFLA_STATS           = C.IFLA_STATS
	IFLA_COST            = C.IFLA_COST
	IFLA_PRIORITY        = C.IFLA_PRIORITY
	IFLA_MASTER          = C.IFLA_MASTER
	IFLA_WIRELESS        = C.IFLA_WIRELESS
	IFLA_PROTINFO        = C.IFLA_PROTINFO
	IFLA_TXQLEN          = C.IFLA_TXQLEN
	IFLA_MAP             = C.IFLA_MAP
	IFLA_WEIGHT          = C.IFLA_WEIGHT
	IFLA_OPERSTATE       = C.IFLA_OPERSTATE
	IFLA_LINKMODE        = C.IFLA_LINKMODE
	IFLA_LINKINFO        = C.IFLA_LINKINFO
	IFLA_NET_NS_PID      = C.IFLA_NET_NS_PID
	IFLA_IFALIAS         = C.IFLA_IFALIAS
	IFLA_NUM_VF          = C.IFLA_NUM_VF
	IFLA_VFINFO_LIST     = C.IFLA_VFINFO_LIST
	IFLA_STATS64         = C.IFLA_STATS64
	IFLA_VF_PORTS        = C.IFLA_VF_PORTS
	IFLA_PORT_SELF       = C.IFLA_PORT_SELF
	IFLA_AF_SPEC         = C.IFLA_AF_SPEC
	IFLA_GROUP           = C.IFLA_GROUP
	IFLA_NET_NS_FD       = C.IFLA_NET_NS_FD
	IFLA_EXT_MASK        = C.IFLA_EXT_MASK
	IFLA_PROMISCUITY     = C.IFLA_PROMISCUITY
	IFLA_NUM_TX_QUEUES   = C.IFLA_NUM_TX_QUEUES
	IFLA_NUM_RX_QUEUES   = C.IFLA_NUM_RX_QUEUES
	IFLA_CARRIER         = C.IFLA_CARRIER
	IFLA_PHYS_PORT_ID    = C.IFLA_PHYS_PORT_ID
	IFLA_CARRIER_CHANGES = C.IFLA_CARRIER_CHANGES
	IFLA_PHYS_SWITCH_ID  = C.IFLA_PHYS_SWITCH_ID
	IFLA_LINK_NETNSID    = C.IFLA_LINK_NETNSID
	IFLA_PHYS_PORT_NAME  = C.IFLA_PHYS_PORT_NAME
	IFLA_PROTO_DOWN      = C.IFLA_PROTO_DOWN
	// IFLA_GSO_MAX_SEGS    = C.IFLA_GSO_MAX_SEGS
	// IFLA_GSO_MAX_SIZE    = C.IFLA_GSO_MAX_SIZE
	//IFLA_PAD = C.IFLA_PAD
	IFLA_XDP = C.IFLA_UNSPEC //_snyh_TODO: C.IFLA_XDP
	//IFLA_EVENT           = C.IFLA_EVENT
	//IFLA_NEW_NETNSID    = C.IFLA_NEW_NETNSID
	//IFLA_IF_NETNSID     = C.IFLA_IF_NETNSID
	IFLA_MAX          = C.IFLA_MAX
	RT_SCOPE_UNIVERSE = C.RT_SCOPE_UNIVERSE
	RT_SCOPE_SITE     = C.RT_SCOPE_SITE
	RT_SCOPE_LINK     = C.RT_SCOPE_LINK
	RT_SCOPE_HOST     = C.RT_SCOPE_HOST
	RT_SCOPE_NOWHERE  = C.RT_SCOPE_NOWHERE
	RT_TABLE_UNSPEC   = C.RT_TABLE_UNSPEC
	RT_TABLE_COMPAT   = C.RT_TABLE_COMPAT
	RT_TABLE_DEFAULT  = C.RT_TABLE_DEFAULT
	RT_TABLE_MAIN     = C.RT_TABLE_MAIN
	RT_TABLE_LOCAL    = C.RT_TABLE_LOCAL
	RT_TABLE_MAX      = C.RT_TABLE_MAX
	RTA_UNSPEC        = C.RTA_UNSPEC
	RTA_DST           = C.RTA_DST
	RTA_SRC           = C.RTA_SRC
	RTA_IIF           = C.RTA_IIF
	RTA_OIF           = C.RTA_OIF
	RTA_GATEWAY       = C.RTA_GATEWAY
	RTA_PRIORITY      = C.RTA_PRIORITY
	RTA_PREFSRC       = C.RTA_PREFSRC
	RTA_METRICS       = C.RTA_METRICS
	RTA_MULTIPATH     = C.RTA_MULTIPATH
	RTA_FLOW          = C.RTA_FLOW
	RTA_CACHEINFO     = C.RTA_CACHEINFO
	RTA_TABLE         = C.RTA_TABLE
	RTA_MARK          = C.RTA_MARK
	RTA_MFC_STATS     = C.RTA_MFC_STATS
	RTA_VIA           = C.RTA_VIA
	RTA_NEWDST        = C.RTA_NEWDST
	RTA_PREF          = C.RTA_PREF
	RTA_ENCAP_TYPE    = C.RTA_ENCAP_TYPE
	RTA_ENCAP         = C.RTA_ENCAP
	//RTA_EXPIRES         = C.RTA_EXPIRES
	//RTA_PAD             = C.RTA_PAD
	//RTA_UID             = C.RTA_UID
	//RTA_TTL_PROPAGATE   = C.RTA_TTL_PROPAGATE
	//RTA_IP_PROTO        = C.RTA_IP_PROTO
	//RTA_SPORT           = C.RTA_SPORT
	//RTA_DPORT           = C.RTA_DPORT
	RTN_UNSPEC          = C.RTN_UNSPEC
	RTN_UNICAST         = C.RTN_UNICAST
	RTN_LOCAL           = C.RTN_LOCAL
	RTN_BROADCAST       = C.RTN_BROADCAST
	RTN_ANYCAST         = C.RTN_ANYCAST
	RTN_MULTICAST       = C.RTN_MULTICAST
	RTN_BLACKHOLE       = C.RTN_BLACKHOLE
	RTN_UNREACHABLE     = C.RTN_UNREACHABLE
	RTN_PROHIBIT        = C.RTN_PROHIBIT
	RTN_THROW           = C.RTN_THROW
	RTN_NAT             = C.RTN_NAT
	RTN_XRESOLVE        = C.RTN_XRESOLVE
	RTNLGRP_NONE        = C.RTNLGRP_NONE
	RTNLGRP_LINK        = C.RTNLGRP_LINK
	RTNLGRP_NOTIFY      = C.RTNLGRP_NOTIFY
	RTNLGRP_NEIGH       = C.RTNLGRP_NEIGH
	RTNLGRP_TC          = C.RTNLGRP_TC
	RTNLGRP_IPV4_IFADDR = C.RTNLGRP_IPV4_IFADDR
	RTNLGRP_IPV4_MROUTE = C.RTNLGRP_IPV4_MROUTE
	RTNLGRP_IPV4_ROUTE  = C.RTNLGRP_IPV4_ROUTE
	RTNLGRP_IPV4_RULE   = C.RTNLGRP_IPV4_RULE
	RTNLGRP_IPV6_IFADDR = C.RTNLGRP_IPV6_IFADDR
	RTNLGRP_IPV6_MROUTE = C.RTNLGRP_IPV6_MROUTE
	RTNLGRP_IPV6_ROUTE  = C.RTNLGRP_IPV6_ROUTE
	RTNLGRP_IPV6_IFINFO = C.RTNLGRP_IPV6_IFINFO
	RTNLGRP_IPV6_PREFIX = C.RTNLGRP_IPV6_PREFIX
	RTNLGRP_IPV6_RULE   = C.RTNLGRP_IPV6_RULE
	RTNLGRP_ND_USEROPT  = C.RTNLGRP_ND_USEROPT
	SizeofNlMsghdr      = C.sizeof_struct_nlmsghdr
	SizeofNlMsgerr      = C.sizeof_struct_nlmsgerr
	SizeofRtGenmsg      = C.sizeof_struct_rtgenmsg
	SizeofNlAttr        = C.sizeof_struct_nlattr
	SizeofRtAttr        = C.sizeof_struct_rtattr
	SizeofIfInfomsg     = C.sizeof_struct_ifinfomsg
	SizeofIfAddrmsg     = C.sizeof_struct_ifaddrmsg
	SizeofRtMsg         = C.sizeof_struct_rtmsg
	SizeofRtNexthop     = C.sizeof_struct_rtnexthop
)

type NlMsghdr C.struct_nlmsghdr

type NlMsgerr C.struct_nlmsgerr

type RtGenmsg C.struct_rtgenmsg

type NlAttr C.struct_nlattr

type RtAttr C.struct_rtattr

type IfInfomsg C.struct_ifinfomsg

type IfAddrmsg C.struct_ifaddrmsg

type RtMsg C.struct_rtmsg

type RtNexthop C.struct_rtnexthop

// Linux socket filter

const (
	SizeofSockFilter = C.sizeof_struct_sock_filter
	SizeofSockFprog  = C.sizeof_struct_sock_fprog
)

type SockFilter C.struct_sock_filter

type SockFprog C.struct_sock_fprog

// Inotify

type InotifyEvent C.struct_inotify_event

const SizeofInotifyEvent = C.sizeof_struct_inotify_event

// Ptrace

// Register structures
type PtraceRegs C.PtraceRegs

// Structures contained in PtraceRegs on s390x (exported by mkpost.go)
type PtracePsw C.ptracePsw

type PtraceFpregs C.ptraceFpregs

type PtracePer C.ptracePer

// Misc

type FdSet C.fd_set

type Sysinfo_t C.struct_sysinfo

type Utsname C.struct_utsname

type Ustat_t C.struct_ustat

type EpollEvent C.struct_my_epoll_event

const (
	AT_EMPTY_PATH   = C.AT_EMPTY_PATH
	AT_FDCWD        = C.AT_FDCWD
	AT_NO_AUTOMOUNT = C.AT_NO_AUTOMOUNT
	AT_REMOVEDIR    = C.AT_REMOVEDIR

	AT_STATX_SYNC_AS_STAT = C.AT_STATX_SYNC_AS_STAT
	AT_STATX_FORCE_SYNC   = C.AT_STATX_FORCE_SYNC
	AT_STATX_DONT_SYNC    = C.AT_STATX_DONT_SYNC

	AT_SYMLINK_FOLLOW   = C.AT_SYMLINK_FOLLOW
	AT_SYMLINK_NOFOLLOW = C.AT_SYMLINK_NOFOLLOW

	AT_EACCESS = C.AT_EACCESS
)

type PollFd C.struct_pollfd

const (
	POLLIN    = C.POLLIN
	POLLPRI   = C.POLLPRI
	POLLOUT   = C.POLLOUT
	POLLRDHUP = C.POLLRDHUP
	POLLERR   = C.POLLERR
	POLLHUP   = C.POLLHUP
	POLLNVAL  = C.POLLNVAL
)

type Sigset_t C.sigset_t

const RNDGETENTCNT = C.RNDGETENTCNT

const PERF_IOC_FLAG_GROUP = C.PERF_IOC_FLAG_GROUP

// Terminal handling

type Termios C.termios_t

type Winsize C.struct_winsize

// Taskstats and cgroup stats.

type Taskstats C.struct_taskstats

const (
	TASKSTATS_CMD_UNSPEC                  = C.TASKSTATS_CMD_UNSPEC
	TASKSTATS_CMD_GET                     = C.TASKSTATS_CMD_GET
	TASKSTATS_CMD_NEW                     = C.TASKSTATS_CMD_NEW
	TASKSTATS_TYPE_UNSPEC                 = C.TASKSTATS_TYPE_UNSPEC
	TASKSTATS_TYPE_PID                    = C.TASKSTATS_TYPE_PID
	TASKSTATS_TYPE_TGID                   = C.TASKSTATS_TYPE_TGID
	TASKSTATS_TYPE_STATS                  = C.TASKSTATS_TYPE_STATS
	TASKSTATS_TYPE_AGGR_PID               = C.TASKSTATS_TYPE_AGGR_PID
	TASKSTATS_TYPE_AGGR_TGID              = C.TASKSTATS_TYPE_AGGR_TGID
	TASKSTATS_TYPE_NULL                   = C.TASKSTATS_TYPE_NULL
	TASKSTATS_CMD_ATTR_UNSPEC             = C.TASKSTATS_CMD_ATTR_UNSPEC
	TASKSTATS_CMD_ATTR_PID                = C.TASKSTATS_CMD_ATTR_PID
	TASKSTATS_CMD_ATTR_TGID               = C.TASKSTATS_CMD_ATTR_TGID
	TASKSTATS_CMD_ATTR_REGISTER_CPUMASK   = C.TASKSTATS_CMD_ATTR_REGISTER_CPUMASK
	TASKSTATS_CMD_ATTR_DEREGISTER_CPUMASK = C.TASKSTATS_CMD_ATTR_DEREGISTER_CPUMASK
)

type CGroupStats C.struct_cgroupstats

const (
	CGROUPSTATS_CMD_UNSPEC        = C.__TASKSTATS_CMD_MAX
	CGROUPSTATS_CMD_GET           = C.CGROUPSTATS_CMD_GET
	CGROUPSTATS_CMD_NEW           = C.CGROUPSTATS_CMD_NEW
	CGROUPSTATS_TYPE_UNSPEC       = C.CGROUPSTATS_TYPE_UNSPEC
	CGROUPSTATS_TYPE_CGROUP_STATS = C.CGROUPSTATS_TYPE_CGROUP_STATS
	CGROUPSTATS_CMD_ATTR_UNSPEC   = C.CGROUPSTATS_CMD_ATTR_UNSPEC
	CGROUPSTATS_CMD_ATTR_FD       = C.CGROUPSTATS_CMD_ATTR_FD
)

// Generic netlink

type Genlmsghdr C.struct_genlmsghdr

const (
	CTRL_CMD_UNSPEC            = C.CTRL_CMD_UNSPEC
	CTRL_CMD_NEWFAMILY         = C.CTRL_CMD_NEWFAMILY
	CTRL_CMD_DELFAMILY         = C.CTRL_CMD_DELFAMILY
	CTRL_CMD_GETFAMILY         = C.CTRL_CMD_GETFAMILY
	CTRL_CMD_NEWOPS            = C.CTRL_CMD_NEWOPS
	CTRL_CMD_DELOPS            = C.CTRL_CMD_DELOPS
	CTRL_CMD_GETOPS            = C.CTRL_CMD_GETOPS
	CTRL_CMD_NEWMCAST_GRP      = C.CTRL_CMD_NEWMCAST_GRP
	CTRL_CMD_DELMCAST_GRP      = C.CTRL_CMD_DELMCAST_GRP
	CTRL_CMD_GETMCAST_GRP      = C.CTRL_CMD_GETMCAST_GRP
	CTRL_ATTR_UNSPEC           = C.CTRL_ATTR_UNSPEC
	CTRL_ATTR_FAMILY_ID        = C.CTRL_ATTR_FAMILY_ID
	CTRL_ATTR_FAMILY_NAME      = C.CTRL_ATTR_FAMILY_NAME
	CTRL_ATTR_VERSION          = C.CTRL_ATTR_VERSION
	CTRL_ATTR_HDRSIZE          = C.CTRL_ATTR_HDRSIZE
	CTRL_ATTR_MAXATTR          = C.CTRL_ATTR_MAXATTR
	CTRL_ATTR_OPS              = C.CTRL_ATTR_OPS
	CTRL_ATTR_MCAST_GROUPS     = C.CTRL_ATTR_MCAST_GROUPS
	CTRL_ATTR_OP_UNSPEC        = C.CTRL_ATTR_OP_UNSPEC
	CTRL_ATTR_OP_ID            = C.CTRL_ATTR_OP_ID
	CTRL_ATTR_OP_FLAGS         = C.CTRL_ATTR_OP_FLAGS
	CTRL_ATTR_MCAST_GRP_UNSPEC = C.CTRL_ATTR_MCAST_GRP_UNSPEC
	CTRL_ATTR_MCAST_GRP_NAME   = C.CTRL_ATTR_MCAST_GRP_NAME
	CTRL_ATTR_MCAST_GRP_ID     = C.CTRL_ATTR_MCAST_GRP_ID
)

// CPU affinity

type cpuMask C.__cpu_mask

const (
	_CPU_SETSIZE = C.__CPU_SETSIZE
	_NCPUBITS    = C.__NCPUBITS
)

// Bluetooth

const (
	BDADDR_BREDR     = C.BDADDR_BREDR
	BDADDR_LE_PUBLIC = C.BDADDR_LE_PUBLIC
	BDADDR_LE_RANDOM = C.BDADDR_LE_RANDOM
)

// TCP-MD5 signature.

type SockaddrStorage C.struct_sockaddr_storage

type TCPMD5Sig C.struct_tcp_md5sig

// Disk drive operations.

type HDDriveCmdHdr C.struct_hd_drive_cmd_hdr

type HDGeometry C.struct_hd_geometry

type HDDriveID C.struct_hd_driveid

const (
	ST_MANDLOCK    = C.ST_MANDLOCK
	ST_NOATIME     = C.ST_NOATIME
	ST_NODEV       = C.ST_NODEV
	ST_NODIRATIME  = C.ST_NODIRATIME
	ST_NOEXEC      = C.ST_NOEXEC
	ST_NOSUID      = C.ST_NOSUID
	ST_RDONLY      = C.ST_RDONLY
	ST_RELATIME    = C.ST_RELATIME
	ST_SYNCHRONOUS = C.ST_SYNCHRONOUS
)

// TPacket

type TpacketHdr C.struct_tpacket_hdr

type Tpacket2Hdr C.struct_tpacket2_hdr

type Tpacket3Hdr C.struct_tpacket3_hdr

type TpacketHdrVariant1 C.struct_tpacket_hdr_variant1

type TpacketBlockDesc C.struct_tpacket_block_desc

type TpacketReq C.struct_tpacket_req

type TpacketReq3 C.struct_tpacket_req3

type TpacketStats C.struct_tpacket_stats

type TpacketStatsV3 C.struct_tpacket_stats_v3

type TpacketAuxdata C.struct_tpacket_auxdata

const (
	TPACKET_V1 = C.TPACKET_V1
	TPACKET_V2 = C.TPACKET_V2
	TPACKET_V3 = C.TPACKET_V3
)

const (
	SizeofTpacketHdr  = C.sizeof_struct_tpacket_hdr
	SizeofTpacket2Hdr = C.sizeof_struct_tpacket2_hdr
	SizeofTpacket3Hdr = C.sizeof_struct_tpacket3_hdr
)

// netfilter
// generated using:
// perl -nlE '/^\s*(NF\w+)/ && say "$1 = C.$1"' /usr/include/linux/netfilter.h
const (
	NF_INET_PRE_ROUTING  = C.NF_INET_PRE_ROUTING
	NF_INET_LOCAL_IN     = C.NF_INET_LOCAL_IN
	NF_INET_FORWARD      = C.NF_INET_FORWARD
	NF_INET_LOCAL_OUT    = C.NF_INET_LOCAL_OUT
	NF_INET_POST_ROUTING = C.NF_INET_POST_ROUTING
	NF_INET_NUMHOOKS     = C.NF_INET_NUMHOOKS
)

const (
	NF_NETDEV_INGRESS  = C.NF_NETDEV_INGRESS
	NF_NETDEV_NUMHOOKS = C.NF_NETDEV_NUMHOOKS
)

const (
	NFPROTO_UNSPEC   = C.NFPROTO_UNSPEC
	NFPROTO_INET     = C.NFPROTO_INET
	NFPROTO_IPV4     = C.NFPROTO_IPV4
	NFPROTO_ARP      = C.NFPROTO_ARP
	NFPROTO_NETDEV   = C.NFPROTO_NETDEV
	NFPROTO_BRIDGE   = C.NFPROTO_BRIDGE
	NFPROTO_IPV6     = C.NFPROTO_IPV6
	NFPROTO_DECNET   = C.NFPROTO_DECNET
	NFPROTO_NUMPROTO = C.NFPROTO_NUMPROTO
)

type RTCTime C.struct_rtc_time

type RTCWkAlrm C.struct_rtc_wkalrm

type RTCPLLInfo C.struct_rtc_pll_info

// BLKPG ioctl:

type BlkpgIoctlArg C.struct_blkpg_ioctl_arg

type BlkpgPartition C.struct_my_blkpg_partition

const (
	BLKPG                  = C.BLKPG
	BLKPG_ADD_PARTITION    = C.BLKPG_ADD_PARTITION
	BLKPG_DEL_PARTITION    = C.BLKPG_DEL_PARTITION
	BLKPG_RESIZE_PARTITION = C.BLKPG_RESIZE_PARTITION
)
