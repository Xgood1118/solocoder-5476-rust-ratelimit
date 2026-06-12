use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum KeySource {
    Header,
    Query,
    Body,
    Cookie,
    Ip,
    Path,
    Global,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyExtractor {
    pub source: KeySource,
    pub expression: String,
}

impl KeyExtractor {
    pub fn new(source: KeySource, expression: &str) -> Self {
        Self {
            source,
            expression: expression.to_string(),
        }
    }

    pub fn global() -> Self {
        Self {
            source: KeySource::Global,
            expression: "global".to_string(),
        }
    }

    pub fn ip() -> Self {
        Self {
            source: KeySource::Ip,
            expression: "ip".to_string(),
        }
    }

    pub fn header(name: &str) -> Self {
        Self {
            source: KeySource::Header,
            expression: name.to_string(),
        }
    }

    pub fn query(name: &str) -> Self {
        Self {
            source: KeySource::Query,
            expression: name.to_string(),
        }
    }

    pub fn body(path: &str) -> Self {
        Self {
            source: KeySource::Body,
            expression: path.to_string(),
        }
    }

    pub fn cookie(name: &str) -> Self {
        Self {
            source: KeySource::Cookie,
            expression: name.to_string(),
        }
    }

    pub fn extract(
        &self,
        headers: &http::HeaderMap,
        query_params: &HashMap<String, String>,
        body: Option<&serde_json::Value>,
        cookies: &HashMap<String, String>,
        client_ip: &str,
        request_path: &str,
    ) -> Option<String> {
        match self.source {
            KeySource::Global => Some("global".to_string()),
            KeySource::Ip => Some(client_ip.to_string()),
            KeySource::Path => Some(request_path.to_string()),
            KeySource::Header => headers
                .get(&self.expression)
                .and_then(|v| v.to_str().ok())
                .map(|s| s.to_string()),
            KeySource::Query => query_params.get(&self.expression).cloned(),
            KeySource::Cookie => cookies.get(&self.expression).cloned(),
            KeySource::Body => {
                if let Some(json_body) = body {
                    extract_json_path(json_body, &self.expression)
                } else {
                    None
                }
            }
        }
    }
}

fn extract_json_path(value: &serde_json::Value, path: &str) -> Option<String> {
    let path = path.trim_start_matches("$.");
    let parts: Vec<&str> = path.split('.').collect();

    let mut current = value;

    for part in parts {
        match current {
            serde_json::Value::Object(map) => {
                if let Some(v) = map.get(part) {
                    current = v;
                } else {
                    return None;
                }
            }
            serde_json::Value::Array(arr) => {
                if let Ok(idx) = part.parse::<usize>() {
                    if let Some(v) = arr.get(idx) {
                        current = v;
                    } else {
                        return None;
                    }
                } else {
                    return None;
                }
            }
            _ => return None,
        }
    }

    match current {
        serde_json::Value::String(s) => Some(s.clone()),
        serde_json::Value::Number(n) => Some(n.to_string()),
        serde_json::Value::Bool(b) => Some(b.to_string()),
        _ => None,
    }
}

pub fn parse_cookies(headers: &http::HeaderMap) -> HashMap<String, String> {
    let mut cookies = HashMap::new();

    if let Some(cookie_header) = headers.get("Cookie") {
        if let Ok(cookie_str) = cookie_header.to_str() {
            for cookie in cookie_str.split(';') {
                let cookie = cookie.trim();
                if let Some((name, value)) = cookie.split_once('=') {
                    cookies.insert(name.trim().to_string(), value.trim().to_string());
                }
            }
        }
    }

    cookies
}

#[cfg(test)]
mod tests {
    use super::*;
    use http::HeaderMap;

    #[test]
    fn test_extract_header() {
        let mut headers = HeaderMap::new();
        headers.insert("X-User-Id", "12345".parse().unwrap());

        let extractor = KeyExtractor::header("X-User-Id");
        let result = extractor.extract(
            &headers,
            &HashMap::new(),
            None,
            &HashMap::new(),
            "127.0.0.1",
            "/test",
        );

        assert_eq!(result, Some("12345".to_string()));
    }

    #[test]
    fn test_extract_body_json() {
        let body = serde_json::json!({
            "user": {
                "id": "67890",
                "name": "test"
            }
        });

        let extractor = KeyExtractor::body("$.user.id");
        let result = extractor.extract(
            &HeaderMap::new(),
            &HashMap::new(),
            Some(&body),
            &HashMap::new(),
            "127.0.0.1",
            "/test",
        );

        assert_eq!(result, Some("67890".to_string()));
    }

    #[test]
    fn test_extract_body_nested_not_panic() {
        let body = serde_json::json!({
            "user": {
                "id": "67890"
            }
        });

        let extractor = KeyExtractor::body("$.user.profile.name");
        let result = extractor.extract(
            &HeaderMap::new(),
            &HashMap::new(),
            Some(&body),
            &HashMap::new(),
            "127.0.0.1",
            "/test",
        );

        assert_eq!(result, None);
    }
}
