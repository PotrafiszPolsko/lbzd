#include "nlohmann/json.hpp"
#include "transaction.hpp"
#include "block.hpp"

void to_json(nlohmann::json &result , const c_vout &vout);
void to_json(nlohmann::json &result , const c_vin &vin);
void to_json(nlohmann::json &result , const c_transaction &tx);
void to_json(nlohmann::json &result, const t_signature_type &signature );
void to_json(nlohmann::json &result , const c_header &header);
void to_json(nlohmann::json &result , const c_block &block);
void from_json(const nlohmann::json &input, c_vin &vin);
void from_json(const nlohmann::json &input, c_vout &vout);
void from_json(const nlohmann::json &input, c_transaction &tx);
