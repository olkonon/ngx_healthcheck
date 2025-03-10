//
// Created by o.kononenko on 19.02.2025.
//
#ifndef NGX_HTTP_DYNAMIC_HEALTHCHECK_H
#define NGX_HTTP_DYNAMIC_HEALTHCHECK_H

#include <nginx.h>
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


#ifdef __cplusplus
extern "C" {
#endif
ngx_int_t ngx_http_dynamic_healthcheck_upstream_status_handler(ngx_http_request_t *r);
ngx_int_t ngx_http_dynamic_healthcheck_stream_status_handler(ngx_http_request_t *r);

#ifdef __cplusplus
}
#endif


#endif //NGX_HTTP_DYNAMIC_HEALTHCHECK_H
