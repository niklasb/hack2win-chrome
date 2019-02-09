#pragma once

#include <cstdint>

namespace v8 {
namespace debug {

struct ConsoleCallArguments {
	uint64_t* implicit_args;
	uint64_t* values;
	uint32_t length;
};

}
}

struct GURL {
	char pad[0x80];
};

namespace base {
struct BasicStringPiece {
	char* ptr;
	size_t length;
};
}

namespace content {
struct AppCacheBackend {
	struct Vtable {
		void(*RegisterHost)(AppCacheBackend*, int);
		void(*UnregisterHost)(AppCacheBackend*, int);
		void* pad1;
		void(*SelectCache)(AppCacheBackend*, int, GURL*, int64_t, GURL*);
	};

	Vtable* vtable;
};

struct WebApplicationCacheHostImpl {
	char pad[0x10];
	AppCacheBackend* backend;
};
}

namespace blink {


// blink_core!blink::ApplicationCacheHost
struct ApplicationCacheHost {
	char pad[0x30];
	content::WebApplicationCacheHostImpl* host;
};

// blink_core!blink::DocumentLoader
struct DocumentLoader {
	char pad[0x848];
	ApplicationCacheHost* application_cache_host;
};

// blink_core!blink::FrameLoader
struct FrameLoader {
	char pad[0x20];
	DocumentLoader* document_loader;
};

// blink_core!blink::LocalFrame
struct LocalFrame {
	char pad[0x508];
	FrameLoader loader;
};

// blink_core!blink::Document
struct Document {
	DocumentLoader* Loader() {
		return frame->loader.document_loader;
	}

	char pad[0x208];
	LocalFrame* frame;
};
}

bool patch_chrome();