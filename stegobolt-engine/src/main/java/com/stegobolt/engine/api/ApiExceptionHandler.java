package com.stegobolt.engine.api;

import com.stegobolt.engine.api.dto.ErrorBody;
import com.stegobolt.engine.core.StegoException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.HttpMediaTypeNotSupportedException;
import org.springframework.web.HttpRequestMethodNotSupportedException;
import org.springframework.web.bind.MissingServletRequestParameterException;
import org.springframework.web.method.annotation.MethodArgumentTypeMismatchException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.multipart.MaxUploadSizeExceededException;
import org.springframework.web.multipart.MultipartException;
import org.springframework.web.multipart.support.MissingServletRequestPartException;

/**
 * Uniform, zero-knowledge error mapping. Messages are operator-safe status
 * strings — stack traces stay in the server log, payload data never does.
 */
@RestControllerAdvice
public class ApiExceptionHandler {

    private static final Logger log = LoggerFactory.getLogger(ApiExceptionHandler.class);

    @ExceptionHandler(StegoException.class)
    public ResponseEntity<ErrorBody> handleStego(StegoException e) {
        log.warn("stego failure of type {}", e.getClass().getSimpleName());
        return ResponseEntity.badRequest()
                .body(new ErrorBody("stego_error", e.getMessage()));
    }

    @ExceptionHandler(MaxUploadSizeExceededException.class)
    public ResponseEntity<ErrorBody> handleTooLarge(MaxUploadSizeExceededException e) {
        return ResponseEntity.status(HttpStatus.PAYLOAD_TOO_LARGE)
                .body(new ErrorBody("payload_too_large", "Upload exceeds the 64 MiB in-memory request budget"));
    }

    @ExceptionHandler(MissingServletRequestPartException.class)
    public ResponseEntity<ErrorBody> handleMissingPart(MissingServletRequestPartException e) {
        return ResponseEntity.badRequest()
                .body(new ErrorBody("missing_part", "Required multipart field missing: " + e.getRequestPartName()));
    }

    @ExceptionHandler(MissingServletRequestParameterException.class)
    public ResponseEntity<ErrorBody> handleMissingParameter(MissingServletRequestParameterException e) {
        return ResponseEntity.badRequest()
                .body(new ErrorBody("missing_parameter", "Required request field missing: " + e.getParameterName()));
    }

    @ExceptionHandler(MethodArgumentTypeMismatchException.class)
    public ResponseEntity<ErrorBody> handleBadParameter(MethodArgumentTypeMismatchException e) {
        return ResponseEntity.badRequest()
                .body(new ErrorBody("invalid_parameter", "A request field has an invalid value"));
    }

    @ExceptionHandler(HttpMediaTypeNotSupportedException.class)
    public ResponseEntity<ErrorBody> handleUnsupportedMedia(HttpMediaTypeNotSupportedException e) {
        return ResponseEntity.status(HttpStatus.UNSUPPORTED_MEDIA_TYPE)
                .body(new ErrorBody("unsupported_media", "Send the carrier as multipart/form-data"));
    }

    @ExceptionHandler(MultipartException.class)
    public ResponseEntity<ErrorBody> handleMultipart(MultipartException e) {
        return ResponseEntity.status(HttpStatus.UNSUPPORTED_MEDIA_TYPE)
                .body(new ErrorBody("unsupported_media", "Send the carrier as multipart/form-data with a cover field"));
    }

    @ExceptionHandler(HttpRequestMethodNotSupportedException.class)
    public ResponseEntity<ErrorBody> handleMethod(HttpRequestMethodNotSupportedException e) {
        return ResponseEntity.status(HttpStatus.METHOD_NOT_ALLOWED)
                .body(new ErrorBody("method_not_allowed", "This engine route accepts POST requests only"));
    }

    @ExceptionHandler(Exception.class)
    public ResponseEntity<ErrorBody> handleAny(Exception e) {
        // Generic message only — never echo raw exception content (zero payload logging).
        log.error("unhandled engine failure of type {}", e.getClass().getSimpleName());
        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                .body(new ErrorBody("engine_error", "Engine processing failed — see server log for the failure class"));
    }
}
