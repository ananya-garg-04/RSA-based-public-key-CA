from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from typing import ClassVar as _ClassVar, Mapping as _Mapping, Optional as _Optional, Union as _Union

DESCRIPTOR: _descriptor.FileDescriptor

class CAPublicKey(_message.Message):
    __slots__ = ("n", "d")
    N_FIELD_NUMBER: _ClassVar[int]
    D_FIELD_NUMBER: _ClassVar[int]
    n: str
    d: str
    def __init__(self, n: _Optional[str] = ..., d: _Optional[str] = ...) -> None: ...

class Certificate(_message.Message):
    __slots__ = ("id", "n", "e", "timestamp", "duration", "caId", "signature")
    ID_FIELD_NUMBER: _ClassVar[int]
    N_FIELD_NUMBER: _ClassVar[int]
    E_FIELD_NUMBER: _ClassVar[int]
    TIMESTAMP_FIELD_NUMBER: _ClassVar[int]
    DURATION_FIELD_NUMBER: _ClassVar[int]
    CAID_FIELD_NUMBER: _ClassVar[int]
    SIGNATURE_FIELD_NUMBER: _ClassVar[int]
    id: str
    n: str
    e: str
    timestamp: int
    duration: int
    caId: str
    signature: str
    def __init__(self, id: _Optional[str] = ..., n: _Optional[str] = ..., e: _Optional[str] = ..., timestamp: _Optional[int] = ..., duration: _Optional[int] = ..., caId: _Optional[str] = ..., signature: _Optional[str] = ...) -> None: ...

class RegisterClientRequest(_message.Message):
    __slots__ = ("clientId", "n", "e")
    CLIENTID_FIELD_NUMBER: _ClassVar[int]
    N_FIELD_NUMBER: _ClassVar[int]
    E_FIELD_NUMBER: _ClassVar[int]
    clientId: str
    n: str
    e: str
    def __init__(self, clientId: _Optional[str] = ..., n: _Optional[str] = ..., e: _Optional[str] = ...) -> None: ...

class CertificateRequest(_message.Message):
    __slots__ = ("clientId",)
    CLIENTID_FIELD_NUMBER: _ClassVar[int]
    clientId: str
    def __init__(self, clientId: _Optional[str] = ...) -> None: ...

class CertificateVerifyRequest(_message.Message):
    __slots__ = ("certificate",)
    CERTIFICATE_FIELD_NUMBER: _ClassVar[int]
    certificate: Certificate
    def __init__(self, certificate: _Optional[_Union[Certificate, _Mapping]] = ...) -> None: ...

class CertificateVerifyResponse(_message.Message):
    __slots__ = ("isValid",)
    ISVALID_FIELD_NUMBER: _ClassVar[int]
    isValid: bool
    def __init__(self, isValid: bool = ...) -> None: ...

class CAPublicKeyRequest(_message.Message):
    __slots__ = ("clientId",)
    CLIENTID_FIELD_NUMBER: _ClassVar[int]
    clientId: str
    def __init__(self, clientId: _Optional[str] = ...) -> None: ...

class RegisterClientResponse(_message.Message):
    __slots__ = ("success",)
    SUCCESS_FIELD_NUMBER: _ClassVar[int]
    success: bool
    def __init__(self, success: bool = ...) -> None: ...

class EncryptedMessage(_message.Message):
    __slots__ = ("message",)
    MESSAGE_FIELD_NUMBER: _ClassVar[int]
    message: str
    def __init__(self, message: _Optional[str] = ...) -> None: ...

class Acknowledgement(_message.Message):
    __slots__ = ("response",)
    RESPONSE_FIELD_NUMBER: _ClassVar[int]
    response: str
    def __init__(self, response: _Optional[str] = ...) -> None: ...
