#include <rpc/rpc.h>
#include <nfs/nfs.h>
#include <linux/nfs2.h>
#include <linux/nfs3.h>
#include <rpc/xdr.h>
 
#include "automount.h"

static int rpc_ping_proto(const char *host,
			  unsigned long nfs_version, const char *proto,
			  long seconds, long micros)
{
	CLIENT *client;
	struct timeval tout;
	enum clnt_stat stat;

	client = clnt_create(host, NFS_PROGRAM, nfs_version, proto);
	if (client == NULL) {
		return 0;
	}

	tout.tv_sec = seconds;
	tout.tv_usec = micros;

	clnt_control(client, CLSET_TIMEOUT, (char *)&tout);
	clnt_control(client, CLSET_RETRY_TIMEOUT, (char *)&tout);

	stat = clnt_call(client, NFSPROC_NULL,
			 (xdrproc_t)xdr_void, 0, (xdrproc_t)xdr_void, 0, tout);

	clnt_destroy(client);

	if (stat != RPC_SUCCESS) {
		return 0;
	}

	return 1;
}

static unsigned int rpc_ping_v2(const char *host, long seconds, long micros)
{
	unsigned int status = RPC_PING_FAIL;

	status = rpc_ping_proto(host, NFS2_VERSION, "udp", seconds, micros);
	if (status)
		return RPC_PING_V2 | RPC_PING_UDP;

	status = rpc_ping_proto(host, NFS2_VERSION, "tcp", seconds, micros);
	if (status)
		return RPC_PING_V2 | RPC_PING_TCP;

	return status;
}

static unsigned int rpc_ping_v3(const char *host, long seconds, long micros)
{
	unsigned int status = RPC_PING_FAIL;

	status = rpc_ping_proto(host, NFS3_VERSION, "udp", seconds, micros);
	if (status)
		return RPC_PING_V3 | RPC_PING_UDP;

	status = rpc_ping_proto(host, NFS3_VERSION, "tcp", seconds, micros);
	if (status)
		return RPC_PING_V3 | RPC_PING_TCP;

	return status;
}

unsigned int rpc_ping(const char *host, long seconds, long micros)
{
	unsigned int status;

	status = rpc_ping_v2(host, seconds, micros);
	if (status)
		return status;

	status = rpc_ping_v3(host, seconds, micros);
	
	return status;
}

static double elapsed(struct timeval start, struct timeval end)
{
	double t1, t2;
	t1 =  (double)start.tv_sec + (double)start.tv_usec/(1000*1000);
	t2 =  (double)end.tv_sec + (double)end.tv_usec/(1000*1000);
	return t2-t1;
}

int rpc_time(const char *host,
	     unsigned int ping_vers, unsigned int ping_proto,
	     long seconds, long micros, double *result)
{
	int status;
	double taken;
	struct timeval start, end;
	struct timezone tz;
	char *proto = (ping_proto & RPC_PING_UDP) ? "udp" : "tcp";

	gettimeofday(&start, &tz);
	status = rpc_ping_proto(host, ping_vers, proto, seconds, micros);
	gettimeofday(&end, &tz);

	if (!status) {
		return 0;
	}

	taken = elapsed(start, end);

	if (result != NULL) {
		*result = taken;
	}

	return status;
}

