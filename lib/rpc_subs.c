#include <rpc/rpc.h>
#include <nfs/nfs.h>
#include <linux/nfs2.h>
#include <rpc/xdr.h>
 
int rpc_ping(const char *host, long seconds, long micros)
{
	CLIENT *client;
	struct timeval tout;
	enum clnt_stat stat;

	client = clnt_create(host, NFS_PROGRAM, NFS2_VERSION, "udp");
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

static double elapsed(struct timeval start, struct timeval end)
{
	double t1, t2;
	t1 =  (double)start.tv_sec + (double)start.tv_usec/(1000*1000);
	t2 =  (double)end.tv_sec + (double)end.tv_usec/(1000*1000);
	return t2-t1;
}

int rpc_time(const char *host, int seconds, int micros, double *result)
{
	CLIENT *client;
	struct timeval tout;
	enum clnt_stat stat;
	struct timeval start, end;
	struct timezone tz;
	double taken;

	client = clnt_create(host, NFS_PROGRAM, NFS2_VERSION, "udp");
	if (client == NULL) {
		return 0;
	}

	tout.tv_sec = seconds;
	tout.tv_usec = micros;

	clnt_control(client, CLSET_TIMEOUT, (char *)&tout);
	clnt_control(client, CLSET_RETRY_TIMEOUT, (char *)&tout);

	gettimeofday(&start, &tz);
	stat = clnt_call(client, NFSPROC_NULL,
			(xdrproc_t)xdr_void, 0, (xdrproc_t)xdr_void, 0, tout);
	gettimeofday(&end, &tz);

	clnt_destroy(client);

	if (stat != RPC_SUCCESS) {
		return 0;
	}

	taken = elapsed(start, end);

	if (result != NULL) {
		*result = taken;
	}

	return 1;
}

