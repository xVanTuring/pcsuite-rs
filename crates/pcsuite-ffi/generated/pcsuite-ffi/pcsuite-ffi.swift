public func pcsuite_log_init() {
    __swift_bridge__$pcsuite_log_init()
}
public func pcsuite_abi_version() -> UInt32 {
    __swift_bridge__$pcsuite_abi_version()
}
public func pcsuite_connect_usb() throws -> PcSession {
    try { let val = __swift_bridge__$pcsuite_connect_usb(); if val.is_ok { return PcSession(ptr: val.ok_or_err!) } else { throw RustString(ptr: val.ok_or_err!) } }()
}
public func pcsuite_connect_lan<GenericIntoRustString: IntoRustString>(_ phone_ip: GenericIntoRustString, _ remote: Bool) throws -> PcSession {
    try { let val = __swift_bridge__$pcsuite_connect_lan({ let rustString = phone_ip.intoRustString(); rustString.isOwned = false; return rustString.ptr }(), remote); if val.is_ok { return PcSession(ptr: val.ok_or_err!) } else { throw RustString(ptr: val.ok_or_err!) } }()
}

public class PcScreen: PcScreenRefMut {
    var isOwned: Bool = true

    public override init(ptr: UnsafeMutableRawPointer) {
        super.init(ptr: ptr)
    }

    deinit {
        if isOwned {
            __swift_bridge__$PcScreen$_free(ptr)
        }
    }
}
public class PcScreenRefMut: PcScreenRef {
    public override init(ptr: UnsafeMutableRawPointer) {
        super.init(ptr: ptr)
    }
}
public class PcScreenRef {
    var ptr: UnsafeMutableRawPointer

    public init(ptr: UnsafeMutableRawPointer) {
        self.ptr = ptr
    }
}
extension PcScreenRef {
    public func next_frame() -> RustVec<UInt8> {
        RustVec(ptr: __swift_bridge__$PcScreen$next_frame(ptr))
    }

    public func stop() {
        __swift_bridge__$PcScreen$stop(ptr)
    }

    public func next_privacy_event() -> RustString {
        RustString(ptr: __swift_bridge__$PcScreen$next_privacy_event(ptr))
    }

    public func next_input_cursor() -> RustString {
        RustString(ptr: __swift_bridge__$PcScreen$next_input_cursor(ptr))
    }
}
extension PcScreen: Vectorizable {
    public static func vecOfSelfNew() -> UnsafeMutableRawPointer {
        __swift_bridge__$Vec_PcScreen$new()
    }

    public static func vecOfSelfFree(vecPtr: UnsafeMutableRawPointer) {
        __swift_bridge__$Vec_PcScreen$drop(vecPtr)
    }

    public static func vecOfSelfPush(vecPtr: UnsafeMutableRawPointer, value: PcScreen) {
        __swift_bridge__$Vec_PcScreen$push(vecPtr, {value.isOwned = false; return value.ptr;}())
    }

    public static func vecOfSelfPop(vecPtr: UnsafeMutableRawPointer) -> Optional<Self> {
        let pointer = __swift_bridge__$Vec_PcScreen$pop(vecPtr)
        if pointer == nil {
            return nil
        } else {
            return (PcScreen(ptr: pointer!) as! Self)
        }
    }

    public static func vecOfSelfGet(vecPtr: UnsafeMutableRawPointer, index: UInt) -> Optional<PcScreenRef> {
        let pointer = __swift_bridge__$Vec_PcScreen$get(vecPtr, index)
        if pointer == nil {
            return nil
        } else {
            return PcScreenRef(ptr: pointer!)
        }
    }

    public static func vecOfSelfGetMut(vecPtr: UnsafeMutableRawPointer, index: UInt) -> Optional<PcScreenRefMut> {
        let pointer = __swift_bridge__$Vec_PcScreen$get_mut(vecPtr, index)
        if pointer == nil {
            return nil
        } else {
            return PcScreenRefMut(ptr: pointer!)
        }
    }

    public static func vecOfSelfAsPtr(vecPtr: UnsafeMutableRawPointer) -> UnsafePointer<PcScreenRef> {
        UnsafePointer<PcScreenRef>(OpaquePointer(__swift_bridge__$Vec_PcScreen$as_ptr(vecPtr)))
    }

    public static func vecOfSelfLen(vecPtr: UnsafeMutableRawPointer) -> UInt {
        __swift_bridge__$Vec_PcScreen$len(vecPtr)
    }
}


public class PcSession: PcSessionRefMut {
    var isOwned: Bool = true

    public override init(ptr: UnsafeMutableRawPointer) {
        super.init(ptr: ptr)
    }

    deinit {
        if isOwned {
            __swift_bridge__$PcSession$_free(ptr)
        }
    }
}
public class PcSessionRefMut: PcSessionRef {
    public override init(ptr: UnsafeMutableRawPointer) {
        super.init(ptr: ptr)
    }
}
public class PcSessionRef {
    var ptr: UnsafeMutableRawPointer

    public init(ptr: UnsafeMutableRawPointer) {
        self.ptr = ptr
    }
}
extension PcSessionRef {
    public func start_screen(_ max_size: Int64) throws -> PcScreen {
        try { let val = __swift_bridge__$PcSession$start_screen(ptr, max_size); if val.is_ok { return PcScreen(ptr: val.ok_or_err!) } else { throw RustString(ptr: val.ok_or_err!) } }()
    }

    public func enable_clipboard(_ recv: Bool, _ send: Bool) throws -> () {
        try { let val = __swift_bridge__$PcSession$enable_clipboard(ptr, recv, send); if val != nil { throw RustString(ptr: val!) } else { return } }()
    }

    public func enable_verify() {
        __swift_bridge__$PcSession$enable_verify(ptr)
    }

    public func next_verify_code() -> RustString {
        RustString(ptr: __swift_bridge__$PcSession$next_verify_code(ptr))
    }

    public func stop_verify() {
        __swift_bridge__$PcSession$stop_verify(ptr)
    }

    public func wait_disconnect() -> RustString {
        RustString(ptr: __swift_bridge__$PcSession$wait_disconnect(ptr))
    }

    public func stop_watch() {
        __swift_bridge__$PcSession$stop_watch(ptr)
    }

    public func mouse(_ action: UInt8, _ button: UInt8, _ x: Int64, _ y: Int64, _ w: Int64, _ h: Int64) -> Bool {
        __swift_bridge__$PcSession$mouse(ptr, action, button, x, y, w, h)
    }

    public func scroll(_ vscroll: Int64, _ x: Int64, _ y: Int64, _ w: Int64, _ h: Int64) -> Bool {
        __swift_bridge__$PcSession$scroll(ptr, vscroll, x, y, w, h)
    }

    public func text<GenericIntoRustString: IntoRustString>(_ s: GenericIntoRustString) -> Bool {
        __swift_bridge__$PcSession$text(ptr, { let rustString = s.intoRustString(); rustString.isOwned = false; return rustString.ptr }())
    }

    public func delete_surrounding(_ before: Int64, _ after: Int64) -> Bool {
        __swift_bridge__$PcSession$delete_surrounding(ptr, before, after)
    }

    public func tap(_ x: Int64, _ y: Int64, _ w: Int64, _ h: Int64) -> Bool {
        __swift_bridge__$PcSession$tap(ptr, x, y, w, h)
    }

    public func key(_ keycode: Int64) -> Bool {
        __swift_bridge__$PcSession$key(ptr, keycode)
    }
}
extension PcSession: Vectorizable {
    public static func vecOfSelfNew() -> UnsafeMutableRawPointer {
        __swift_bridge__$Vec_PcSession$new()
    }

    public static func vecOfSelfFree(vecPtr: UnsafeMutableRawPointer) {
        __swift_bridge__$Vec_PcSession$drop(vecPtr)
    }

    public static func vecOfSelfPush(vecPtr: UnsafeMutableRawPointer, value: PcSession) {
        __swift_bridge__$Vec_PcSession$push(vecPtr, {value.isOwned = false; return value.ptr;}())
    }

    public static func vecOfSelfPop(vecPtr: UnsafeMutableRawPointer) -> Optional<Self> {
        let pointer = __swift_bridge__$Vec_PcSession$pop(vecPtr)
        if pointer == nil {
            return nil
        } else {
            return (PcSession(ptr: pointer!) as! Self)
        }
    }

    public static func vecOfSelfGet(vecPtr: UnsafeMutableRawPointer, index: UInt) -> Optional<PcSessionRef> {
        let pointer = __swift_bridge__$Vec_PcSession$get(vecPtr, index)
        if pointer == nil {
            return nil
        } else {
            return PcSessionRef(ptr: pointer!)
        }
    }

    public static func vecOfSelfGetMut(vecPtr: UnsafeMutableRawPointer, index: UInt) -> Optional<PcSessionRefMut> {
        let pointer = __swift_bridge__$Vec_PcSession$get_mut(vecPtr, index)
        if pointer == nil {
            return nil
        } else {
            return PcSessionRefMut(ptr: pointer!)
        }
    }

    public static func vecOfSelfAsPtr(vecPtr: UnsafeMutableRawPointer) -> UnsafePointer<PcSessionRef> {
        UnsafePointer<PcSessionRef>(OpaquePointer(__swift_bridge__$Vec_PcSession$as_ptr(vecPtr)))
    }

    public static func vecOfSelfLen(vecPtr: UnsafeMutableRawPointer) -> UInt {
        __swift_bridge__$Vec_PcSession$len(vecPtr)
    }
}



