extern __thread int testval0 __attribute((tls_model("initial-exec")));
extern __thread int testval1 __attribute((tls_model("initial-exec")));

__thread int testval0 = 1;
__thread int testval1 = 4;
int _testval0 = 3;
int _testval1 = 2;
