/*
 * Adyen Checkout API
 *
 * The version of the OpenAPI document: 70
 * Contact: developer-experience@adyen.com
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */


package com.adyen.model.checkout;

import java.util.Objects;
import java.util.Arrays;
import com.google.gson.TypeAdapter;
import com.google.gson.annotations.JsonAdapter;
import com.google.gson.annotations.SerializedName;
import com.google.gson.stream.JsonReader;
import com.google.gson.stream.JsonWriter;
import io.swagger.annotations.ApiModel;
import io.swagger.annotations.ApiModelProperty;
import java.io.IOException;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonArray;
import com.google.gson.JsonDeserializationContext;
import com.google.gson.JsonDeserializer;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParseException;
import com.google.gson.TypeAdapterFactory;
import com.google.gson.reflect.TypeToken;

import java.lang.reflect.Type;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;

import com.adyen.model.checkout.JSON;

/**
 * VisaCheckoutDetails
 */

public class VisaCheckoutDetails {
  public static final String SERIALIZED_NAME_CHECKOUT_ATTEMPT_ID = "checkoutAttemptId";
  @SerializedName(SERIALIZED_NAME_CHECKOUT_ATTEMPT_ID)
  private String checkoutAttemptId;

  /**
   * The funding source that should be used when multiple sources are available. For Brazilian combo cards, by default the funding source is credit. To use debit, set this value to **debit**.
   */
  @JsonAdapter(FundingSourceEnum.Adapter.class)
  public enum FundingSourceEnum {
    DEBIT("debit");

    private String value;

    FundingSourceEnum(String value) {
      this.value = value;
    }

    public String getValue() {
      return value;
    }

    @Override
    public String toString() {
      return String.valueOf(value);
    }

    public static FundingSourceEnum fromValue(String value) {
      for (FundingSourceEnum b : FundingSourceEnum.values()) {
        if (b.value.equals(value)) {
          return b;
        }
      }
      throw new IllegalArgumentException("Unexpected value '" + value + "'");
    }

    public static class Adapter extends TypeAdapter<FundingSourceEnum> {
      @Override
      public void write(final JsonWriter jsonWriter, final FundingSourceEnum enumeration) throws IOException {
        jsonWriter.value(enumeration.getValue());
      }

      @Override
      public FundingSourceEnum read(final JsonReader jsonReader) throws IOException {
        String value =  jsonReader.nextString();
        return FundingSourceEnum.fromValue(value);
      }
    }
  }

  public static final String SERIALIZED_NAME_FUNDING_SOURCE = "fundingSource";
  @SerializedName(SERIALIZED_NAME_FUNDING_SOURCE)
  private FundingSourceEnum fundingSource;

  /**
   * **visacheckout**
   */
  @JsonAdapter(TypeEnum.Adapter.class)
  public enum TypeEnum {
    VISACHECKOUT("visacheckout");

    private String value;

    TypeEnum(String value) {
      this.value = value;
    }

    public String getValue() {
      return value;
    }

    @Override
    public String toString() {
      return String.valueOf(value);
    }

    public static TypeEnum fromValue(String value) {
      for (TypeEnum b : TypeEnum.values()) {
        if (b.value.equals(value)) {
          return b;
        }
      }
      throw new IllegalArgumentException("Unexpected value '" + value + "'");
    }

    public static class Adapter extends TypeAdapter<TypeEnum> {
      @Override
      public void write(final JsonWriter jsonWriter, final TypeEnum enumeration) throws IOException {
        jsonWriter.value(enumeration.getValue());
      }

      @Override
      public TypeEnum read(final JsonReader jsonReader) throws IOException {
        String value =  jsonReader.nextString();
        return TypeEnum.fromValue(value);
      }
    }
  }

  public static final String SERIALIZED_NAME_TYPE = "type";
  @SerializedName(SERIALIZED_NAME_TYPE)
  private TypeEnum type = TypeEnum.VISACHECKOUT;

  public static final String SERIALIZED_NAME_VISA_CHECKOUT_CALL_ID = "visaCheckoutCallId";
  @SerializedName(SERIALIZED_NAME_VISA_CHECKOUT_CALL_ID)
  private String visaCheckoutCallId;

  public VisaCheckoutDetails() { 
  }

  public VisaCheckoutDetails checkoutAttemptId(String checkoutAttemptId) {
    
    this.checkoutAttemptId = checkoutAttemptId;
    return this;
  }

   /**
   * The checkout attempt identifier.
   * @return checkoutAttemptId
  **/
  @ApiModelProperty(value = "The checkout attempt identifier.")

  public String getCheckoutAttemptId() {
    return checkoutAttemptId;
  }


  public void setCheckoutAttemptId(String checkoutAttemptId) {
    this.checkoutAttemptId = checkoutAttemptId;
  }


  public VisaCheckoutDetails fundingSource(FundingSourceEnum fundingSource) {
    
    this.fundingSource = fundingSource;
    return this;
  }

   /**
   * The funding source that should be used when multiple sources are available. For Brazilian combo cards, by default the funding source is credit. To use debit, set this value to **debit**.
   * @return fundingSource
  **/
  @ApiModelProperty(value = "The funding source that should be used when multiple sources are available. For Brazilian combo cards, by default the funding source is credit. To use debit, set this value to **debit**.")

  public FundingSourceEnum getFundingSource() {
    return fundingSource;
  }


  public void setFundingSource(FundingSourceEnum fundingSource) {
    this.fundingSource = fundingSource;
  }


  public VisaCheckoutDetails type(TypeEnum type) {
    
    this.type = type;
    return this;
  }

   /**
   * **visacheckout**
   * @return type
  **/
  @ApiModelProperty(value = "**visacheckout**")

  public TypeEnum getType() {
    return type;
  }


  public void setType(TypeEnum type) {
    this.type = type;
  }


  public VisaCheckoutDetails visaCheckoutCallId(String visaCheckoutCallId) {
    
    this.visaCheckoutCallId = visaCheckoutCallId;
    return this;
  }

   /**
   * The Visa Click to Pay Call ID value. When your shopper selects a payment and/or a shipping address from Visa Click to Pay, you will receive a Visa Click to Pay Call ID.
   * @return visaCheckoutCallId
  **/
  @ApiModelProperty(required = true, value = "The Visa Click to Pay Call ID value. When your shopper selects a payment and/or a shipping address from Visa Click to Pay, you will receive a Visa Click to Pay Call ID.")

  public String getVisaCheckoutCallId() {
    return visaCheckoutCallId;
  }


  public void setVisaCheckoutCallId(String visaCheckoutCallId) {
    this.visaCheckoutCallId = visaCheckoutCallId;
  }



  @Override
  public boolean equals(Object o) {
    if (this == o) {
      return true;
    }
    if (o == null || getClass() != o.getClass()) {
      return false;
    }
    VisaCheckoutDetails visaCheckoutDetails = (VisaCheckoutDetails) o;
    return Objects.equals(this.checkoutAttemptId, visaCheckoutDetails.checkoutAttemptId) &&
        Objects.equals(this.fundingSource, visaCheckoutDetails.fundingSource) &&
        Objects.equals(this.type, visaCheckoutDetails.type) &&
        Objects.equals(this.visaCheckoutCallId, visaCheckoutDetails.visaCheckoutCallId);
  }

  @Override
  public int hashCode() {
    return Objects.hash(checkoutAttemptId, fundingSource, type, visaCheckoutCallId);
  }

  @Override
  public String toString() {
    StringBuilder sb = new StringBuilder();
    sb.append("class VisaCheckoutDetails {\n");
    sb.append("    checkoutAttemptId: ").append(toIndentedString(checkoutAttemptId)).append("\n");
    sb.append("    fundingSource: ").append(toIndentedString(fundingSource)).append("\n");
    sb.append("    type: ").append(toIndentedString(type)).append("\n");
    sb.append("    visaCheckoutCallId: ").append(toIndentedString(visaCheckoutCallId)).append("\n");
    sb.append("}");
    return sb.toString();
  }

  /**
   * Convert the given object to string with each line indented by 4 spaces
   * (except the first line).
   */
  private String toIndentedString(Object o) {
    if (o == null) {
      return "null";
    }
    return o.toString().replace("\n", "\n    ");
  }


  public static HashSet<String> openapiFields;
  public static HashSet<String> openapiRequiredFields;

  static {
    // a set of all properties/fields (JSON key names)
    openapiFields = new HashSet<String>();
    openapiFields.add("checkoutAttemptId");
    openapiFields.add("fundingSource");
    openapiFields.add("type");
    openapiFields.add("visaCheckoutCallId");

    // a set of required properties/fields (JSON key names)
    openapiRequiredFields = new HashSet<String>();
    openapiRequiredFields.add("visaCheckoutCallId");
  }

 /**
  * Validates the JSON Object and throws an exception if issues found
  *
  * @param jsonObj JSON Object
  * @throws IOException if the JSON Object is invalid with respect to VisaCheckoutDetails
  */
  public static void validateJsonObject(JsonObject jsonObj) throws IOException {
      if (jsonObj == null) {
        if (VisaCheckoutDetails.openapiRequiredFields.isEmpty()) {
          return;
        } else { // has required fields
          throw new IllegalArgumentException(String.format("The required field(s) %s in VisaCheckoutDetails is not found in the empty JSON string", VisaCheckoutDetails.openapiRequiredFields.toString()));
        }
      }

      Set<Entry<String, JsonElement>> entries = jsonObj.entrySet();
      // check to see if the JSON string contains additional fields
      for (Entry<String, JsonElement> entry : entries) {
        if (!VisaCheckoutDetails.openapiFields.contains(entry.getKey())) {
          throw new IllegalArgumentException(String.format("The field `%s` in the JSON string is not defined in the `VisaCheckoutDetails` properties. JSON: %s", entry.getKey(), jsonObj.toString()));
        }
      }

      // check to make sure all required properties/fields are present in the JSON string
      for (String requiredField : VisaCheckoutDetails.openapiRequiredFields) {
        if (jsonObj.get(requiredField) == null) {
          throw new IllegalArgumentException(String.format("The required field `%s` is not found in the JSON string: %s", requiredField, jsonObj.toString()));
        }
      }
      // validate the optional field checkoutAttemptId
      if (jsonObj.get("checkoutAttemptId") != null && !jsonObj.get("checkoutAttemptId").isJsonPrimitive()) {
        throw new IllegalArgumentException(String.format("Expected the field `checkoutAttemptId` to be a primitive type in the JSON string but got `%s`", jsonObj.get("checkoutAttemptId").toString()));
      }
      // ensure the field fundingSource can be parsed to an enum value
      if (jsonObj.get("fundingSource") != null) {
        if(!jsonObj.get("fundingSource").isJsonPrimitive()) {
          throw new IllegalArgumentException(String.format("Expected the field `fundingSource` to be a primitive type in the JSON string but got `%s`", jsonObj.get("fundingSource").toString()));
        }
        FundingSourceEnum.fromValue(jsonObj.get("fundingSource").getAsString());
      }
      // ensure the field type can be parsed to an enum value
      if (jsonObj.get("type") != null) {
        if(!jsonObj.get("type").isJsonPrimitive()) {
          throw new IllegalArgumentException(String.format("Expected the field `type` to be a primitive type in the JSON string but got `%s`", jsonObj.get("type").toString()));
        }
        TypeEnum.fromValue(jsonObj.get("type").getAsString());
      }
      // validate the optional field visaCheckoutCallId
      if (jsonObj.get("visaCheckoutCallId") != null && !jsonObj.get("visaCheckoutCallId").isJsonPrimitive()) {
        throw new IllegalArgumentException(String.format("Expected the field `visaCheckoutCallId` to be a primitive type in the JSON string but got `%s`", jsonObj.get("visaCheckoutCallId").toString()));
      }
  }

  public static class CustomTypeAdapterFactory implements TypeAdapterFactory {
    @SuppressWarnings("unchecked")
    @Override
    public <T> TypeAdapter<T> create(Gson gson, TypeToken<T> type) {
       if (!VisaCheckoutDetails.class.isAssignableFrom(type.getRawType())) {
         return null; // this class only serializes 'VisaCheckoutDetails' and its subtypes
       }
       final TypeAdapter<JsonElement> elementAdapter = gson.getAdapter(JsonElement.class);
       final TypeAdapter<VisaCheckoutDetails> thisAdapter
                        = gson.getDelegateAdapter(this, TypeToken.get(VisaCheckoutDetails.class));

       return (TypeAdapter<T>) new TypeAdapter<VisaCheckoutDetails>() {
           @Override
           public void write(JsonWriter out, VisaCheckoutDetails value) throws IOException {
             JsonObject obj = thisAdapter.toJsonTree(value).getAsJsonObject();
             elementAdapter.write(out, obj);
           }

           @Override
           public VisaCheckoutDetails read(JsonReader in) throws IOException {
             JsonObject jsonObj = elementAdapter.read(in).getAsJsonObject();
             validateJsonObject(jsonObj);
             return thisAdapter.fromJsonTree(jsonObj);
           }

       }.nullSafe();
    }
  }

 /**
  * Create an instance of VisaCheckoutDetails given an JSON string
  *
  * @param jsonString JSON string
  * @return An instance of VisaCheckoutDetails
  * @throws IOException if the JSON string is invalid with respect to VisaCheckoutDetails
  */
  public static VisaCheckoutDetails fromJson(String jsonString) throws IOException {
    return JSON.getGson().fromJson(jsonString, VisaCheckoutDetails.class);
  }

 /**
  * Convert an instance of VisaCheckoutDetails to an JSON string
  *
  * @return JSON string
  */
  public String toJson() {
    return JSON.getGson().toJson(this);
  }
}
