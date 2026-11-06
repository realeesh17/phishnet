# Existing data model

There is no persisted application database or ORM model. The runtime exchanges URL analysis request/response objects and transient provider/cache state. The compatibility-critical entities are `AnalyzeRequest`, `AnalysisResponse`, `Indicator`, `SourceCheck`, and the threat-intelligence provider result.
