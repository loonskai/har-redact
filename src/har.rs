use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HarFile {
    pub log: Log,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Log {
    pub version: String,
    pub creator: Creator,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub browser: Option<Creator>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pages: Option<Vec<Page>>,
    pub entries: Vec<Entry>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub comment: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Creator {
    pub name: String,
    pub version: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub comment: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Page {
    #[serde(rename = "startedDateTime")]
    pub started_date_time: String,
    pub id: String,
    pub title: String,
    #[serde(rename = "pageTimings")]
    pub page_timings: PageTimings,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub comment: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PageTimings {
    #[serde(rename = "onContentLoad", skip_serializing_if = "Option::is_none")]
    pub on_content_load: Option<f64>,
    #[serde(rename = "onLoad", skip_serializing_if = "Option::is_none")]
    pub on_load: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub comment: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Entry {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pageref: Option<String>,
    #[serde(rename = "startedDateTime")]
    pub started_date_time: String,
    pub time: f64,
    pub request: Request,
    pub response: Response,
    pub cache: Cache,
    pub timings: Timings,
    #[serde(rename = "serverIPAddress", skip_serializing_if = "Option::is_none")]
    pub server_ip_address: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub connection: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub comment: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Request {
    pub method: String,
    pub url: String,
    #[serde(rename = "httpVersion")]
    pub http_version: String,
    pub cookies: Vec<Cookie>,
    pub headers: Vec<Header>,
    #[serde(rename = "queryString")]
    pub query_string: Vec<QueryParam>,
    #[serde(rename = "postData", skip_serializing_if = "Option::is_none")]
    pub post_data: Option<PostData>,
    #[serde(rename = "headersSize")]
    pub headers_size: i64,
    #[serde(rename = "bodySize")]
    pub body_size: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub comment: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Response {
    pub status: i32,
    #[serde(rename = "statusText")]
    pub status_text: String,
    #[serde(rename = "httpVersion")]
    pub http_version: String,
    pub cookies: Vec<Cookie>,
    pub headers: Vec<Header>,
    pub content: Content,
    #[serde(rename = "redirectURL")]
    pub redirect_url: String,
    #[serde(rename = "headersSize")]
    pub headers_size: i64,
    #[serde(rename = "bodySize")]
    pub body_size: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub comment: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Header {
    pub name: String,
    pub value: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub comment: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Cookie {
    pub name: String,
    pub value: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub domain: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires: Option<String>,
    #[serde(rename = "httpOnly", skip_serializing_if = "Option::is_none")]
    pub http_only: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub secure: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub comment: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueryParam {
    pub name: String,
    pub value: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub comment: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PostData {
    #[serde(rename = "mimeType")]
    pub mime_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub params: Option<Vec<Param>>,
    pub text: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub comment: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Param {
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub value: Option<String>,
    #[serde(rename = "fileName", skip_serializing_if = "Option::is_none")]
    pub file_name: Option<String>,
    #[serde(rename = "contentType", skip_serializing_if = "Option::is_none")]
    pub content_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub comment: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Content {
    pub size: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub compression: Option<i64>,
    #[serde(rename = "mimeType")]
    pub mime_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub text: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub encoding: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub comment: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Cache {
    #[serde(rename = "beforeRequest", skip_serializing_if = "Option::is_none")]
    pub before_request: Option<CacheState>,
    #[serde(rename = "afterRequest", skip_serializing_if = "Option::is_none")]
    pub after_request: Option<CacheState>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub comment: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CacheState {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires: Option<String>,
    #[serde(rename = "lastAccess")]
    pub last_access: String,
    #[serde(rename = "eTag")]
    pub etag: String,
    #[serde(rename = "hitCount")]
    pub hit_count: i32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub comment: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Timings {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub blocked: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dns: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub connect: Option<f64>,
    pub send: f64,
    pub wait: f64,
    pub receive: f64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ssl: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub comment: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_deserialize_minimal_har() {
        let har_json = r#"{
            "log": {
                "version": "1.2",
                "creator": {
                    "name": "Test",
                    "version": "1.0"
                },
                "entries": []
            }
        }"#;

        let har: Result<HarFile, _> = serde_json::from_str(har_json);
        assert!(har.is_ok());
        let har = har.unwrap();
        assert_eq!(har.log.version, "1.2");
        assert_eq!(har.log.creator.name, "Test");
    }

    #[test]
    fn test_serialize_har() {
        let har = HarFile {
            log: Log {
                version: "1.2".to_string(),
                creator: Creator {
                    name: "Test".to_string(),
                    version: "1.0".to_string(),
                    comment: None,
                },
                browser: None,
                pages: None,
                entries: vec![],
                comment: None,
            },
        };

        let json = serde_json::to_string(&har);
        assert!(json.is_ok());
    }

    #[test]
    fn test_header_serialization() {
        let header = Header {
            name: "Authorization".to_string(),
            value: "Bearer token123".to_string(),
            comment: None,
        };

        let json = serde_json::to_string(&header).unwrap();
        assert!(json.contains("Authorization"));
        assert!(json.contains("Bearer token123"));
    }
}
