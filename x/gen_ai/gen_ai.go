package gen_ai

import "github.com/iostrovok/kibana-fields"

// All available fields as constants
const (
	GenAiAgentDescription        fields.Field = "gen_ai.agent.description"         // Free-form description of the GenAI agent provided by the application.
	GenAiAgentID                 fields.Field = "gen_ai.agent.id"                  // The unique identifier of the GenAI agent.
	GenAiAgentName               fields.Field = "gen_ai.agent.name"                // Human-readable name of the GenAI agent provided by the application.
	GenAiOperationName           fields.Field = "gen_ai.operation.name"            // The name of the operation being performed.
	GenAiOutputType              fields.Field = "gen_ai.output.type"               // Represents the content type requested by the client.
	GenAiRequestChoiceCount      fields.Field = "gen_ai.request.choice.count"      // The target number of candidate completions to return.
	GenAiRequestEncodingFormats  fields.Field = "gen_ai.request.encoding_formats"  // The encoding formats requested in an embeddings operation, if specified.
	GenAiRequestFrequencyPenalty fields.Field = "gen_ai.request.frequency_penalty" // The frequency penalty setting for the GenAI request.
	GenAiRequestMaxTokens        fields.Field = "gen_ai.request.max_tokens"        // The maximum number of tokens the model generates for a request.
	GenAiRequestModel            fields.Field = "gen_ai.request.model"             // The name of the GenAI model a request is being made to.
	GenAiRequestPresencePenalty  fields.Field = "gen_ai.request.presence_penalty"  // The presence penalty setting for the GenAI request.
	GenAiRequestSeed             fields.Field = "gen_ai.request.seed"              // Requests with same seed value more likely to return same result.
	GenAiRequestStopSequences    fields.Field = "gen_ai.request.stop_sequences"    // List of sequences that the model will use to stop generating further tokens.
	GenAiRequestTemperature      fields.Field = "gen_ai.request.temperature"       // The temperature setting for the GenAI request.
	GenAiRequestTopK             fields.Field = "gen_ai.request.top_k"             // The top_k sampling setting for the GenAI request.
	GenAiRequestTopP             fields.Field = "gen_ai.request.top_p"             // The top_p sampling setting for the GenAI request.
	GenAiResponseFinishReasons   fields.Field = "gen_ai.response.finish_reasons"   // Array of reasons the model stopped generating tokens, corresponding to each generation received.
	GenAiResponseID              fields.Field = "gen_ai.response.id"               // The unique identifier for the completion.
	GenAiResponseModel           fields.Field = "gen_ai.response.model"            // The name of the model that generated the response.
	GenAiSystem                  fields.Field = "gen_ai.system"                    // The Generative AI product as identified by the client or server instrumentation.
	GenAiTokenType               fields.Field = "gen_ai.token.type"                // The type of token being counted.
	GenAiToolCallID              fields.Field = "gen_ai.tool.call.id"              // The tool call identifier.
	GenAiToolName                fields.Field = "gen_ai.tool.name"                 // Name of the tool utilized by the agent.
	GenAiToolType                fields.Field = "gen_ai.tool.type"                 // Type of the tool utilized by the agent
	GenAiUsageInputTokens        fields.Field = "gen_ai.usage.input_tokens"        // The number of tokens used in the GenAI input (prompt).
	GenAiUsageOutputTokens       fields.Field = "gen_ai.usage.output_tokens"       // The number of tokens used in the GenAI response (completion).

)

// Fields contains all package constants as list
var Fields = []fields.Field{
	GenAiAgentDescription,
	GenAiAgentID,
	GenAiAgentName,
	GenAiOperationName,
	GenAiOutputType,
	GenAiRequestChoiceCount,
	GenAiRequestEncodingFormats,
	GenAiRequestFrequencyPenalty,
	GenAiRequestMaxTokens,
	GenAiRequestModel,
	GenAiRequestPresencePenalty,
	GenAiRequestSeed,
	GenAiRequestStopSequences,
	GenAiRequestTemperature,
	GenAiRequestTopK,
	GenAiRequestTopP,
	GenAiResponseFinishReasons,
	GenAiResponseID,
	GenAiResponseModel,
	GenAiSystem,
	GenAiTokenType,
	GenAiToolCallID,
	GenAiToolName,
	GenAiToolType,
	GenAiUsageInputTokens,
	GenAiUsageOutputTokens,
}

// TypesType describes kibana types of fields to check values
type TypesType struct {
	GenAiAgentDescription        fields.Keyword
	GenAiAgentID                 fields.Keyword
	GenAiAgentName               fields.Keyword
	GenAiOperationName           fields.Keyword
	GenAiOutputType              fields.Keyword
	GenAiRequestChoiceCount      fields.Integer
	GenAiRequestEncodingFormats  fields.Nested
	GenAiRequestFrequencyPenalty fields.Double
	GenAiRequestMaxTokens        fields.Integer
	GenAiRequestModel            fields.Keyword
	GenAiRequestPresencePenalty  fields.Double
	GenAiRequestSeed             fields.Integer
	GenAiRequestStopSequences    fields.Nested
	GenAiRequestTemperature      fields.Double
	GenAiRequestTopK             fields.Double
	GenAiRequestTopP             fields.Double
	GenAiResponseFinishReasons   fields.Nested
	GenAiResponseID              fields.Keyword
	GenAiResponseModel           fields.Keyword
	GenAiSystem                  fields.Keyword
	GenAiTokenType               fields.Keyword
	GenAiToolCallID              fields.Keyword
	GenAiToolName                fields.Keyword
	GenAiToolType                fields.Keyword
	GenAiUsageInputTokens        fields.Integer
	GenAiUsageOutputTokens       fields.Integer
}

var Types TypesType = TypesType{}
