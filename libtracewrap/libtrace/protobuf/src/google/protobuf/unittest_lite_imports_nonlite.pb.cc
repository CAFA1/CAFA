// Generated by the protocol buffer compiler.  DO NOT EDIT!

#define INTERNAL_SUPPRESS_PROTOBUF_FIELD_DEPRECATION
#include "google/protobuf/unittest_lite_imports_nonlite.pb.h"

#include <algorithm>

#include <google/protobuf/stubs/once.h>
#include <google/protobuf/io/coded_stream.h>
#include <google/protobuf/wire_format_lite_inl.h>
// @@protoc_insertion_point(includes)

namespace protobuf_unittest {

void protobuf_ShutdownFile_google_2fprotobuf_2funittest_5flite_5fimports_5fnonlite_2eproto() {
  delete TestLiteImportsNonlite::default_instance_;
}

void protobuf_AddDesc_google_2fprotobuf_2funittest_5flite_5fimports_5fnonlite_2eproto() {
  static bool already_here = false;
  if (already_here) return;
  already_here = true;
  GOOGLE_PROTOBUF_VERIFY_VERSION;

  ::protobuf_unittest::protobuf_AddDesc_google_2fprotobuf_2funittest_2eproto();
  TestLiteImportsNonlite::default_instance_ = new TestLiteImportsNonlite();
  TestLiteImportsNonlite::default_instance_->InitAsDefaultInstance();
  ::google::protobuf::internal::OnShutdown(&protobuf_ShutdownFile_google_2fprotobuf_2funittest_5flite_5fimports_5fnonlite_2eproto);
}

// Force AddDescriptors() to be called at static initialization time.
struct StaticDescriptorInitializer_google_2fprotobuf_2funittest_5flite_5fimports_5fnonlite_2eproto {
  StaticDescriptorInitializer_google_2fprotobuf_2funittest_5flite_5fimports_5fnonlite_2eproto() {
    protobuf_AddDesc_google_2fprotobuf_2funittest_5flite_5fimports_5fnonlite_2eproto();
  }
} static_descriptor_initializer_google_2fprotobuf_2funittest_5flite_5fimports_5fnonlite_2eproto_;


// ===================================================================

#ifndef _MSC_VER
const int TestLiteImportsNonlite::kMessageFieldNumber;
#endif  // !_MSC_VER

TestLiteImportsNonlite::TestLiteImportsNonlite()
  : ::google::protobuf::MessageLite() {
  SharedCtor();
}

void TestLiteImportsNonlite::InitAsDefaultInstance() {
  message_ = const_cast< ::protobuf_unittest::TestAllTypes*>(&::protobuf_unittest::TestAllTypes::default_instance());
}

TestLiteImportsNonlite::TestLiteImportsNonlite(const TestLiteImportsNonlite& from)
  : ::google::protobuf::MessageLite() {
  SharedCtor();
  MergeFrom(from);
}

void TestLiteImportsNonlite::SharedCtor() {
  _cached_size_ = 0;
  message_ = NULL;
  ::memset(_has_bits_, 0, sizeof(_has_bits_));
}

TestLiteImportsNonlite::~TestLiteImportsNonlite() {
  SharedDtor();
}

void TestLiteImportsNonlite::SharedDtor() {
  if (this != default_instance_) {
    delete message_;
  }
}

void TestLiteImportsNonlite::SetCachedSize(int size) const {
  GOOGLE_SAFE_CONCURRENT_WRITES_BEGIN();
  _cached_size_ = size;
  GOOGLE_SAFE_CONCURRENT_WRITES_END();
}
const TestLiteImportsNonlite& TestLiteImportsNonlite::default_instance() {
  if (default_instance_ == NULL) protobuf_AddDesc_google_2fprotobuf_2funittest_5flite_5fimports_5fnonlite_2eproto();  return *default_instance_;
}

TestLiteImportsNonlite* TestLiteImportsNonlite::default_instance_ = NULL;

TestLiteImportsNonlite* TestLiteImportsNonlite::New() const {
  return new TestLiteImportsNonlite;
}

void TestLiteImportsNonlite::Clear() {
  if (_has_bits_[0 / 32] & (0xffu << (0 % 32))) {
    if (has_message()) {
      if (message_ != NULL) message_->::protobuf_unittest::TestAllTypes::Clear();
    }
  }
  ::memset(_has_bits_, 0, sizeof(_has_bits_));
}

bool TestLiteImportsNonlite::MergePartialFromCodedStream(
    ::google::protobuf::io::CodedInputStream* input) {
#define DO_(EXPRESSION) if (!(EXPRESSION)) return false
  ::google::protobuf::uint32 tag;
  while ((tag = input->ReadTag()) != 0) {
    switch (::google::protobuf::internal::WireFormatLite::GetTagFieldNumber(tag)) {
      // optional .protobuf_unittest.TestAllTypes message = 1;
      case 1: {
        if (::google::protobuf::internal::WireFormatLite::GetTagWireType(tag) ==
            ::google::protobuf::internal::WireFormatLite::WIRETYPE_LENGTH_DELIMITED) {
          DO_(::google::protobuf::internal::WireFormatLite::ReadMessageNoVirtual(
               input, mutable_message()));
        } else {
          goto handle_uninterpreted;
        }
        if (input->ExpectAtEnd()) return true;
        break;
      }
      
      default: {
      handle_uninterpreted:
        if (::google::protobuf::internal::WireFormatLite::GetTagWireType(tag) ==
            ::google::protobuf::internal::WireFormatLite::WIRETYPE_END_GROUP) {
          return true;
        }
        DO_(::google::protobuf::internal::WireFormatLite::SkipField(input, tag));
        break;
      }
    }
  }
  return true;
#undef DO_
}

void TestLiteImportsNonlite::SerializeWithCachedSizes(
    ::google::protobuf::io::CodedOutputStream* output) const {
  // optional .protobuf_unittest.TestAllTypes message = 1;
  if (has_message()) {
    ::google::protobuf::internal::WireFormatLite::WriteMessageMaybeToArray(
      1, this->message(), output);
  }
  
}

int TestLiteImportsNonlite::ByteSize() const {
  int total_size = 0;
  
  if (_has_bits_[0 / 32] & (0xffu << (0 % 32))) {
    // optional .protobuf_unittest.TestAllTypes message = 1;
    if (has_message()) {
      total_size += 1 +
        ::google::protobuf::internal::WireFormatLite::MessageSizeNoVirtual(
          this->message());
    }
    
  }
  GOOGLE_SAFE_CONCURRENT_WRITES_BEGIN();
  _cached_size_ = total_size;
  GOOGLE_SAFE_CONCURRENT_WRITES_END();
  return total_size;
}

void TestLiteImportsNonlite::CheckTypeAndMergeFrom(
    const ::google::protobuf::MessageLite& from) {
  MergeFrom(*::google::protobuf::down_cast<const TestLiteImportsNonlite*>(&from));
}

void TestLiteImportsNonlite::MergeFrom(const TestLiteImportsNonlite& from) {
  GOOGLE_CHECK_NE(&from, this);
  if (from._has_bits_[0 / 32] & (0xffu << (0 % 32))) {
    if (from.has_message()) {
      mutable_message()->::protobuf_unittest::TestAllTypes::MergeFrom(from.message());
    }
  }
}

void TestLiteImportsNonlite::CopyFrom(const TestLiteImportsNonlite& from) {
  if (&from == this) return;
  Clear();
  MergeFrom(from);
}

bool TestLiteImportsNonlite::IsInitialized() const {
  
  return true;
}

void TestLiteImportsNonlite::Swap(TestLiteImportsNonlite* other) {
  if (other != this) {
    std::swap(message_, other->message_);
    std::swap(_has_bits_[0], other->_has_bits_[0]);
    std::swap(_cached_size_, other->_cached_size_);
  }
}

::std::string TestLiteImportsNonlite::GetTypeName() const {
  return "protobuf_unittest.TestLiteImportsNonlite";
}


// @@protoc_insertion_point(namespace_scope)

}  // namespace protobuf_unittest

// @@protoc_insertion_point(global_scope)
