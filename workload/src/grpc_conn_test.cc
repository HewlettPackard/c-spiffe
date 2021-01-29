#include "workload.grpc.pb.h"
#include "workload.pb.h"
#include <grpcpp/grpcpp.h>
#include <stdio.h>

using grpc::Channel;
using grpc::ClientContext;
using grpc::ClientReader;
using grpc::Status;

int main(void) {
  std::shared_ptr<Channel> chan = grpc::CreateChannel(
      "unix:///tmp/agent.sock", grpc::InsecureChannelCredentials());

  std::unique_ptr<SpiffeWorkloadAPI::Stub> stub =
      SpiffeWorkloadAPI::NewStub(chan);
  ClientContext ctx;
  ctx.AddMetadata("workload.spiffe.io", "true");
  X509SVIDRequest req;
  X509SVIDResponse response;

  std::unique_ptr<grpc::ClientReader<X509SVIDResponse>> c_reader =
      stub->FetchX509SVID(&ctx, req);
  int a = c_reader->Read(&response);
  do {
    auto ids = response.svids();
    for (auto &&id : ids) {
      printf("SPIFFE ID: %s\n", id.spiffe_id().c_str());
    }
    a = c_reader->Read(&response);
  } while (a);

  Status status = c_reader->Finish();

  if (status.ok()) {
    std::cout << "Fetched SVIDs " << std::endl;
  } else {
    std::cout << "Fetch failed.\nError code: " << status.error_code()
              << "(Message:" << status.error_message() << ")" << std::endl;
  }

  return 0;
}
