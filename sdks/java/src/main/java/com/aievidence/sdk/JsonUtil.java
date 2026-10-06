package com.aievidence.sdk;

import java.util.*;

/**
 * Lightweight, zero-dependency JSON serialization and parsing utility.
 */
public final class JsonUtil {

    private JsonUtil() {}

    /**
     * Serializes a DecisionEvent to standard JSON matching the ML Ingest API schema.
     */
    public static String toJson(DecisionEvent event) {
        if (event == null) {
            return "null";
        }
        StringBuilder sb = new StringBuilder("{");
        boolean first = true;

        if (event.getAiSystemId() != null) {
            sb.append("\"ai_system_id\":").append(quote(event.getAiSystemId()));
            first = false;
        }

        if (event.getModelVersion() != null) {
            if (!first) sb.append(",");
            sb.append("\"model_version\":").append(quote(event.getModelVersion()));
            first = false;
        }

        if (event.getArtifactHash() != null) {
            if (!first) sb.append(",");
            sb.append("\"artifact_hash\":").append(quote(event.getArtifactHash()));
            first = false;
        }

        if (event.getFeatures() != null && !event.getFeatures().isEmpty()) {
            if (!first) sb.append(",");
            sb.append("\"features\":").append(toJson(event.getFeatures()));
            first = false;
        }

        if (event.getScore() != null) {
            if (!first) sb.append(",");
            sb.append("\"score\":").append(event.getScore());
            first = false;
        }

        if (event.getDecision() != null) {
            if (!first) sb.append(",");
            sb.append("\"decision\":").append(quote(event.getDecision()));
            first = false;
        }

        if (event.getExplanation() != null) {
            if (!first) sb.append(",");
            sb.append("\"explanation\":").append(toJson(event.getExplanation()));
            first = false;
        }

        if (event.getCorrelationId() != null) {
            if (!first) sb.append(",");
            sb.append("\"correlation_id\":").append(quote(event.getCorrelationId()));
            first = false;
        }

        if (!first) sb.append(",");
        sb.append("\"requires_approval\":").append(event.isRequiresApproval());
        first = false;

        if (event.getCreatorId() != null) {
            sb.append(",");
            sb.append("\"creator_id\":").append(quote(event.getCreatorId()));
        }

        sb.append("}");
        return sb.toString();
    }

    /**
     * Serializes an Explanation object.
     */
    public static String toJson(Explanation explanation) {
        if (explanation == null) {
            return "null";
        }
        StringBuilder sb = new StringBuilder("{");
        sb.append("\"method\":").append(quote(explanation.getMethod())).append(",");
        sb.append("\"top_features\":[");
        List<FeatureImpact> list = explanation.getTopFeatures();
        for (int i = 0; i < list.size(); i++) {
            if (i > 0) sb.append(",");
            FeatureImpact fi = list.get(i);
            sb.append("{");
            sb.append("\"feature\":").append(quote(fi.getFeature())).append(",");
            sb.append("\"importance\":").append(fi.getImportance());
            if (fi.getContribution() != null) {
                sb.append(",\"contribution\":").append(quote(fi.getContribution()));
            }
            if (fi.getValue() != null) {
                sb.append(",\"value\":").append(toJson(fi.getValue()));
            }
            sb.append("}");
        }
        sb.append("]}");
        return sb.toString();
    }

    /**
     * Serializes arbitrary Java Object (Map, List, String, Number, Boolean) to JSON.
     */
    @SuppressWarnings("unchecked")
    public static String toJson(Object obj) {
        if (obj == null) {
            return "null";
        }
        if (obj instanceof String) {
            return quote((String) obj);
        }
        if (obj instanceof Number || obj instanceof Boolean) {
            return obj.toString();
        }
        if (obj instanceof Map) {
            Map<?, ?> map = (Map<?, ?>) obj;
            StringBuilder sb = new StringBuilder("{");
            boolean first = true;
            for (Map.Entry<?, ?> entry : map.entrySet()) {
                if (!first) sb.append(",");
                sb.append(quote(String.valueOf(entry.getKey()))).append(":");
                sb.append(toJson(entry.getValue()));
                first = false;
            }
            sb.append("}");
            return sb.toString();
        }
        if (obj instanceof Iterable) {
            StringBuilder sb = new StringBuilder("[");
            boolean first = true;
            for (Object item : (Iterable<?>) obj) {
                if (!first) sb.append(",");
                sb.append(toJson(item));
                first = false;
            }
            sb.append("]");
            return sb.toString();
        }
        if (obj instanceof Object[]) {
            StringBuilder sb = new StringBuilder("[");
            Object[] arr = (Object[]) obj;
            for (int i = 0; i < arr.length; i++) {
                if (i > 0) sb.append(",");
                sb.append(toJson(arr[i]));
            }
            sb.append("]");
            return sb.toString();
        }
        return quote(obj.toString());
    }

    private static String quote(String string) {
        if (string == null) return "\"\"";
        StringBuilder sb = new StringBuilder("\"");
        for (int i = 0; i < string.length(); i++) {
            char c = string.charAt(i);
            switch (c) {
                case '\\': sb.append("\\\\"); break;
                case '"': sb.append("\\\""); break;
                case '\b': sb.append("\\b"); break;
                case '\f': sb.append("\\f"); break;
                case '\n': sb.append("\\n"); break;
                case '\r': sb.append("\\r"); break;
                case '\t': sb.append("\\t"); break;
                default:
                    if (c < ' ') {
                        String t = "000" + Integer.toHexString(c);
                        sb.append("\\u").append(t.substring(t.length() - 4));
                    } else {
                        sb.append(c);
                    }
            }
        }
        sb.append("\"");
        return sb.toString();
    }

    /**
     * Parses a JSON string into a Map<String, Object>.
     */
    @SuppressWarnings("unchecked")
    public static Map<String, Object> parseJsonObject(String json) {
        if (json == null || json.isBlank()) {
            return Collections.emptyMap();
        }
        Object parsed = parse(json.trim());
        if (parsed instanceof Map) {
            return (Map<String, Object>) parsed;
        }
        return Collections.emptyMap();
    }

    /**
     * Parses a JSON value into Java Object (Map, List, String, Double, Boolean, null).
     */
    public static Object parse(String json) {
        if (json == null || json.isBlank()) {
            return null;
        }
        return new Parser(json.trim()).parseValue();
    }

    private static class Parser {
        private final String src;
        private int pos = 0;

        Parser(String src) {
            this.src = src;
        }

        private void skipWhitespace() {
            while (pos < src.length() && Character.isWhitespace(src.charAt(pos))) {
                pos++;
            }
        }

        private char peek() {
            skipWhitespace();
            return pos < src.length() ? src.charAt(pos) : '\0';
        }

        private char next() {
            skipWhitespace();
            return pos < src.length() ? src.charAt(pos++) : '\0';
        }

        Object parseValue() {
            char c = peek();
            if (c == '{') return parseObject();
            if (c == '[') return parseArray();
            if (c == '"') return parseString();
            if (c == 't' || c == 'f') return parseBoolean();
            if (c == 'n') return parseNull();
            if (c == '-' || Character.isDigit(c)) return parseNumber();
            throw new IllegalArgumentException("Unexpected character at " + pos + ": " + c);
        }

        Map<String, Object> parseObject() {
            next(); // consume '{'
            Map<String, Object> map = new LinkedHashMap<>();
            skipWhitespace();
            if (peek() == '}') {
                next();
                return map;
            }
            while (pos < src.length()) {
                String key = parseString();
                skipWhitespace();
                if (next() != ':') {
                    throw new IllegalArgumentException("Expected ':' at " + pos);
                }
                Object val = parseValue();
                map.put(key, val);
                skipWhitespace();
                char sep = next();
                if (sep == '}') {
                    break;
                } else if (sep != ',') {
                    throw new IllegalArgumentException("Expected ',' or '}' at " + pos + ", got " + sep);
                }
            }
            return map;
        }

        List<Object> parseArray() {
            next(); // consume '['
            List<Object> list = new ArrayList<>();
            skipWhitespace();
            if (peek() == ']') {
                next();
                return list;
            }
            while (pos < src.length()) {
                Object val = parseValue();
                list.add(val);
                skipWhitespace();
                char sep = next();
                if (sep == ']') {
                    break;
                } else if (sep != ',') {
                    throw new IllegalArgumentException("Expected ',' or ']' at " + pos + ", got " + sep);
                }
            }
            return list;
        }

        String parseString() {
            next(); // consume opening quote
            StringBuilder sb = new StringBuilder();
            while (pos < src.length()) {
                char c = src.charAt(pos++);
                if (c == '"') {
                    return sb.toString();
                }
                if (c == '\\') {
                    if (pos >= src.length()) break;
                    char esc = src.charAt(pos++);
                    switch (esc) {
                        case '"': sb.append('"'); break;
                        case '\\': sb.append('\\'); break;
                        case '/': sb.append('/'); break;
                        case 'b': sb.append('\b'); break;
                        case 'f': sb.append('\f'); break;
                        case 'n': sb.append('\n'); break;
                        case 'r': sb.append('\r'); break;
                        case 't': sb.append('\t'); break;
                        case 'u':
                            if (pos + 4 <= src.length()) {
                                String hex = src.substring(pos, pos + 4);
                                sb.append((char) Integer.parseInt(hex, 16));
                                pos += 4;
                            }
                            break;
                        default: sb.append(esc);
                    }
                } else {
                    sb.append(c);
                }
            }
            return sb.toString();
        }

        Boolean parseBoolean() {
            if (src.startsWith("true", pos)) {
                pos += 4;
                return Boolean.TRUE;
            } else if (src.startsWith("false", pos)) {
                pos += 5;
                return Boolean.FALSE;
            }
            throw new IllegalArgumentException("Expected boolean at " + pos);
        }

        Object parseNull() {
            if (src.startsWith("null", pos)) {
                pos += 4;
                return null;
            }
            throw new IllegalArgumentException("Expected null at " + pos);
        }

        Number parseNumber() {
            int start = pos;
            if (pos < src.length() && src.charAt(pos) == '-') pos++;
            while (pos < src.length() && Character.isDigit(src.charAt(pos))) pos++;
            boolean isFloat = false;
            if (pos < src.length() && src.charAt(pos) == '.') {
                isFloat = true;
                pos++;
                while (pos < src.length() && Character.isDigit(src.charAt(pos))) pos++;
            }
            if (pos < src.length() && (src.charAt(pos) == 'e' || src.charAt(pos) == 'E')) {
                isFloat = true;
                pos++;
                if (pos < src.length() && (src.charAt(pos) == '+' || src.charAt(pos) == '-')) pos++;
                while (pos < src.length() && Character.isDigit(src.charAt(pos))) pos++;
            }
            String numStr = src.substring(start, pos);
            if (isFloat) {
                return Double.parseDouble(numStr);
            }
            try {
                return Long.parseLong(numStr);
            } catch (NumberFormatException e) {
                return Double.parseDouble(numStr);
            }
        }
    }
}
