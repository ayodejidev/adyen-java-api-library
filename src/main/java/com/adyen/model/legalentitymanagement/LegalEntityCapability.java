/*
 * Legal Entity Management API
 *
 * The version of the OpenAPI document: 3
 * Contact: developer-experience@adyen.com
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */


package com.adyen.model.legalentitymanagement;

import java.util.Objects;
import java.util.Arrays;
import com.adyen.model.legalentitymanagement.CapabilitySettings;
import com.adyen.model.legalentitymanagement.SupportingEntityCapability;
import com.google.gson.TypeAdapter;
import com.google.gson.annotations.JsonAdapter;
import com.google.gson.annotations.SerializedName;
import com.google.gson.stream.JsonReader;
import com.google.gson.stream.JsonWriter;
import io.swagger.annotations.ApiModel;
import io.swagger.annotations.ApiModelProperty;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

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

import com.adyen.model.legalentitymanagement.JSON;

/**
 * LegalEntityCapability
 */

public class LegalEntityCapability {
  public static final String SERIALIZED_NAME_ALLOWED = "allowed";
  @SerializedName(SERIALIZED_NAME_ALLOWED)
  private Boolean allowed;

  /**
   * The capability level that is allowed for the legal entity.  Possible values: **notApplicable**, **low**, **medium**, **high**.
   */
  @JsonAdapter(AllowedLevelEnum.Adapter.class)
  public enum AllowedLevelEnum {
    HIGH("high"),
    
    LOW("low"),
    
    MEDIUM("medium"),
    
    NOTAPPLICABLE("notApplicable");

    private String value;

    AllowedLevelEnum(String value) {
      this.value = value;
    }

    public String getValue() {
      return value;
    }

    @Override
    public String toString() {
      return String.valueOf(value);
    }

    public static AllowedLevelEnum fromValue(String value) {
      for (AllowedLevelEnum b : AllowedLevelEnum.values()) {
        if (b.value.equals(value)) {
          return b;
        }
      }
      throw new IllegalArgumentException("Unexpected value '" + value + "'");
    }

    public static class Adapter extends TypeAdapter<AllowedLevelEnum> {
      @Override
      public void write(final JsonWriter jsonWriter, final AllowedLevelEnum enumeration) throws IOException {
        jsonWriter.value(enumeration.getValue());
      }

      @Override
      public AllowedLevelEnum read(final JsonReader jsonReader) throws IOException {
        String value =  jsonReader.nextString();
        return AllowedLevelEnum.fromValue(value);
      }
    }
  }

  public static final String SERIALIZED_NAME_ALLOWED_LEVEL = "allowedLevel";
  @SerializedName(SERIALIZED_NAME_ALLOWED_LEVEL)
  private AllowedLevelEnum allowedLevel;

  public static final String SERIALIZED_NAME_ALLOWED_SETTINGS = "allowedSettings";
  @SerializedName(SERIALIZED_NAME_ALLOWED_SETTINGS)
  private CapabilitySettings allowedSettings;

  public static final String SERIALIZED_NAME_REQUESTED = "requested";
  @SerializedName(SERIALIZED_NAME_REQUESTED)
  private Boolean requested;

  /**
   * The requested level of the capability. Some capabilities, such as those used in [card issuing](https://docs.adyen.com/issuing/add-capabilities#capability-levels), have different levels. Levels increase the capability, but also require additional checks and increased monitoring.  Possible values: **notApplicable**, **low**, **medium**, **high**.
   */
  @JsonAdapter(RequestedLevelEnum.Adapter.class)
  public enum RequestedLevelEnum {
    HIGH("high"),
    
    LOW("low"),
    
    MEDIUM("medium"),
    
    NOTAPPLICABLE("notApplicable");

    private String value;

    RequestedLevelEnum(String value) {
      this.value = value;
    }

    public String getValue() {
      return value;
    }

    @Override
    public String toString() {
      return String.valueOf(value);
    }

    public static RequestedLevelEnum fromValue(String value) {
      for (RequestedLevelEnum b : RequestedLevelEnum.values()) {
        if (b.value.equals(value)) {
          return b;
        }
      }
      throw new IllegalArgumentException("Unexpected value '" + value + "'");
    }

    public static class Adapter extends TypeAdapter<RequestedLevelEnum> {
      @Override
      public void write(final JsonWriter jsonWriter, final RequestedLevelEnum enumeration) throws IOException {
        jsonWriter.value(enumeration.getValue());
      }

      @Override
      public RequestedLevelEnum read(final JsonReader jsonReader) throws IOException {
        String value =  jsonReader.nextString();
        return RequestedLevelEnum.fromValue(value);
      }
    }
  }

  public static final String SERIALIZED_NAME_REQUESTED_LEVEL = "requestedLevel";
  @SerializedName(SERIALIZED_NAME_REQUESTED_LEVEL)
  private RequestedLevelEnum requestedLevel;

  public static final String SERIALIZED_NAME_REQUESTED_SETTINGS = "requestedSettings";
  @SerializedName(SERIALIZED_NAME_REQUESTED_SETTINGS)
  private CapabilitySettings requestedSettings;

  public static final String SERIALIZED_NAME_TRANSFER_INSTRUMENTS = "transferInstruments";
  @SerializedName(SERIALIZED_NAME_TRANSFER_INSTRUMENTS)
  private List<SupportingEntityCapability> transferInstruments = null;

  public static final String SERIALIZED_NAME_VERIFICATION_STATUS = "verificationStatus";
  @SerializedName(SERIALIZED_NAME_VERIFICATION_STATUS)
  private String verificationStatus;

  public LegalEntityCapability() { 
  }

  
  public LegalEntityCapability(
     Boolean allowed, 
     AllowedLevelEnum allowedLevel, 
     Boolean requested, 
     RequestedLevelEnum requestedLevel, 
     List<SupportingEntityCapability> transferInstruments, 
     String verificationStatus
  ) {
    this();
    this.allowed = allowed;
    this.allowedLevel = allowedLevel;
    this.requested = requested;
    this.requestedLevel = requestedLevel;
    this.transferInstruments = transferInstruments;
    this.verificationStatus = verificationStatus;
  }

   /**
   * Indicates whether the capability is allowed. Adyen sets this to **true** if the verification is successful 
   * @return allowed
  **/
  @ApiModelProperty(value = "Indicates whether the capability is allowed. Adyen sets this to **true** if the verification is successful ")

  public Boolean getAllowed() {
    return allowed;
  }




   /**
   * The capability level that is allowed for the legal entity.  Possible values: **notApplicable**, **low**, **medium**, **high**.
   * @return allowedLevel
  **/
  @ApiModelProperty(value = "The capability level that is allowed for the legal entity.  Possible values: **notApplicable**, **low**, **medium**, **high**.")

  public AllowedLevelEnum getAllowedLevel() {
    return allowedLevel;
  }




  public LegalEntityCapability allowedSettings(CapabilitySettings allowedSettings) {
    
    this.allowedSettings = allowedSettings;
    return this;
  }

   /**
   * Get allowedSettings
   * @return allowedSettings
  **/
  @ApiModelProperty(value = "")

  public CapabilitySettings getAllowedSettings() {
    return allowedSettings;
  }


  public void setAllowedSettings(CapabilitySettings allowedSettings) {
    this.allowedSettings = allowedSettings;
  }


   /**
   * Indicates whether the capability is requested. To check whether the Legal Entity is permitted to use the capability, 
   * @return requested
  **/
  @ApiModelProperty(value = "Indicates whether the capability is requested. To check whether the Legal Entity is permitted to use the capability, ")

  public Boolean getRequested() {
    return requested;
  }




   /**
   * The requested level of the capability. Some capabilities, such as those used in [card issuing](https://docs.adyen.com/issuing/add-capabilities#capability-levels), have different levels. Levels increase the capability, but also require additional checks and increased monitoring.  Possible values: **notApplicable**, **low**, **medium**, **high**.
   * @return requestedLevel
  **/
  @ApiModelProperty(value = "The requested level of the capability. Some capabilities, such as those used in [card issuing](https://docs.adyen.com/issuing/add-capabilities#capability-levels), have different levels. Levels increase the capability, but also require additional checks and increased monitoring.  Possible values: **notApplicable**, **low**, **medium**, **high**.")

  public RequestedLevelEnum getRequestedLevel() {
    return requestedLevel;
  }




  public LegalEntityCapability requestedSettings(CapabilitySettings requestedSettings) {
    
    this.requestedSettings = requestedSettings;
    return this;
  }

   /**
   * Get requestedSettings
   * @return requestedSettings
  **/
  @ApiModelProperty(value = "")

  public CapabilitySettings getRequestedSettings() {
    return requestedSettings;
  }


  public void setRequestedSettings(CapabilitySettings requestedSettings) {
    this.requestedSettings = requestedSettings;
  }


   /**
   * Capability status for transfer instruments associated with legal entity
   * @return transferInstruments
  **/
  @ApiModelProperty(value = "Capability status for transfer instruments associated with legal entity")

  public List<SupportingEntityCapability> getTransferInstruments() {
    return transferInstruments;
  }




   /**
   * The status of the verification checks for the capability.  Possible values:  * **pending**: Adyen is running the verification.  * **invalid**: The verification failed. Check if the &#x60;errors&#x60; array contains more information.  * **valid**: The verification has been successfully completed.  * **rejected**: Adyen has verified the information, but found reasons to not allow the capability. 
   * @return verificationStatus
  **/
  @ApiModelProperty(value = "The status of the verification checks for the capability.  Possible values:  * **pending**: Adyen is running the verification.  * **invalid**: The verification failed. Check if the `errors` array contains more information.  * **valid**: The verification has been successfully completed.  * **rejected**: Adyen has verified the information, but found reasons to not allow the capability. ")

  public String getVerificationStatus() {
    return verificationStatus;
  }





  @Override
  public boolean equals(Object o) {
    if (this == o) {
      return true;
    }
    if (o == null || getClass() != o.getClass()) {
      return false;
    }
    LegalEntityCapability legalEntityCapability = (LegalEntityCapability) o;
    return Objects.equals(this.allowed, legalEntityCapability.allowed) &&
        Objects.equals(this.allowedLevel, legalEntityCapability.allowedLevel) &&
        Objects.equals(this.allowedSettings, legalEntityCapability.allowedSettings) &&
        Objects.equals(this.requested, legalEntityCapability.requested) &&
        Objects.equals(this.requestedLevel, legalEntityCapability.requestedLevel) &&
        Objects.equals(this.requestedSettings, legalEntityCapability.requestedSettings) &&
        Objects.equals(this.transferInstruments, legalEntityCapability.transferInstruments) &&
        Objects.equals(this.verificationStatus, legalEntityCapability.verificationStatus);
  }

  @Override
  public int hashCode() {
    return Objects.hash(allowed, allowedLevel, allowedSettings, requested, requestedLevel, requestedSettings, transferInstruments, verificationStatus);
  }

  @Override
  public String toString() {
    StringBuilder sb = new StringBuilder();
    sb.append("class LegalEntityCapability {\n");
    sb.append("    allowed: ").append(toIndentedString(allowed)).append("\n");
    sb.append("    allowedLevel: ").append(toIndentedString(allowedLevel)).append("\n");
    sb.append("    allowedSettings: ").append(toIndentedString(allowedSettings)).append("\n");
    sb.append("    requested: ").append(toIndentedString(requested)).append("\n");
    sb.append("    requestedLevel: ").append(toIndentedString(requestedLevel)).append("\n");
    sb.append("    requestedSettings: ").append(toIndentedString(requestedSettings)).append("\n");
    sb.append("    transferInstruments: ").append(toIndentedString(transferInstruments)).append("\n");
    sb.append("    verificationStatus: ").append(toIndentedString(verificationStatus)).append("\n");
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
    openapiFields.add("allowed");
    openapiFields.add("allowedLevel");
    openapiFields.add("allowedSettings");
    openapiFields.add("requested");
    openapiFields.add("requestedLevel");
    openapiFields.add("requestedSettings");
    openapiFields.add("transferInstruments");
    openapiFields.add("verificationStatus");

    // a set of required properties/fields (JSON key names)
    openapiRequiredFields = new HashSet<String>();
  }

 /**
  * Validates the JSON Object and throws an exception if issues found
  *
  * @param jsonObj JSON Object
  * @throws IOException if the JSON Object is invalid with respect to LegalEntityCapability
  */
  public static void validateJsonObject(JsonObject jsonObj) throws IOException {
      if (jsonObj == null) {
        if (LegalEntityCapability.openapiRequiredFields.isEmpty()) {
          return;
        } else { // has required fields
          throw new IllegalArgumentException(String.format("The required field(s) %s in LegalEntityCapability is not found in the empty JSON string", LegalEntityCapability.openapiRequiredFields.toString()));
        }
      }

      Set<Entry<String, JsonElement>> entries = jsonObj.entrySet();
      // check to see if the JSON string contains additional fields
      for (Entry<String, JsonElement> entry : entries) {
        if (!LegalEntityCapability.openapiFields.contains(entry.getKey())) {
          throw new IllegalArgumentException(String.format("The field `%s` in the JSON string is not defined in the `LegalEntityCapability` properties. JSON: %s", entry.getKey(), jsonObj.toString()));
        }
      }
      // ensure the field allowedLevel can be parsed to an enum value
      if (jsonObj.get("allowedLevel") != null) {
        if(!jsonObj.get("allowedLevel").isJsonPrimitive()) {
          throw new IllegalArgumentException(String.format("Expected the field `allowedLevel` to be a primitive type in the JSON string but got `%s`", jsonObj.get("allowedLevel").toString()));
        }
        AllowedLevelEnum.fromValue(jsonObj.get("allowedLevel").getAsString());
      }
      // validate the optional field `allowedSettings`
      if (jsonObj.getAsJsonObject("allowedSettings") != null) {
        CapabilitySettings.validateJsonObject(jsonObj.getAsJsonObject("allowedSettings"));
      }
      // ensure the field requestedLevel can be parsed to an enum value
      if (jsonObj.get("requestedLevel") != null) {
        if(!jsonObj.get("requestedLevel").isJsonPrimitive()) {
          throw new IllegalArgumentException(String.format("Expected the field `requestedLevel` to be a primitive type in the JSON string but got `%s`", jsonObj.get("requestedLevel").toString()));
        }
        RequestedLevelEnum.fromValue(jsonObj.get("requestedLevel").getAsString());
      }
      // validate the optional field `requestedSettings`
      if (jsonObj.getAsJsonObject("requestedSettings") != null) {
        CapabilitySettings.validateJsonObject(jsonObj.getAsJsonObject("requestedSettings"));
      }
      JsonArray jsonArraytransferInstruments = jsonObj.getAsJsonArray("transferInstruments");
      if (jsonArraytransferInstruments != null) {
        // ensure the json data is an array
        if (!jsonObj.get("transferInstruments").isJsonArray()) {
          throw new IllegalArgumentException(String.format("Expected the field `transferInstruments` to be an array in the JSON string but got `%s`", jsonObj.get("transferInstruments").toString()));
        }

        // validate the optional field `transferInstruments` (array)
        for (int i = 0; i < jsonArraytransferInstruments.size(); i++) {
          SupportingEntityCapability.validateJsonObject(jsonArraytransferInstruments.get(i).getAsJsonObject());
        };
      }
      // validate the optional field verificationStatus
      if (jsonObj.get("verificationStatus") != null && !jsonObj.get("verificationStatus").isJsonPrimitive()) {
        throw new IllegalArgumentException(String.format("Expected the field `verificationStatus` to be a primitive type in the JSON string but got `%s`", jsonObj.get("verificationStatus").toString()));
      }
  }

  public static class CustomTypeAdapterFactory implements TypeAdapterFactory {
    @SuppressWarnings("unchecked")
    @Override
    public <T> TypeAdapter<T> create(Gson gson, TypeToken<T> type) {
       if (!LegalEntityCapability.class.isAssignableFrom(type.getRawType())) {
         return null; // this class only serializes 'LegalEntityCapability' and its subtypes
       }
       final TypeAdapter<JsonElement> elementAdapter = gson.getAdapter(JsonElement.class);
       final TypeAdapter<LegalEntityCapability> thisAdapter
                        = gson.getDelegateAdapter(this, TypeToken.get(LegalEntityCapability.class));

       return (TypeAdapter<T>) new TypeAdapter<LegalEntityCapability>() {
           @Override
           public void write(JsonWriter out, LegalEntityCapability value) throws IOException {
             JsonObject obj = thisAdapter.toJsonTree(value).getAsJsonObject();
             elementAdapter.write(out, obj);
           }

           @Override
           public LegalEntityCapability read(JsonReader in) throws IOException {
             JsonObject jsonObj = elementAdapter.read(in).getAsJsonObject();
             validateJsonObject(jsonObj);
             return thisAdapter.fromJsonTree(jsonObj);
           }

       }.nullSafe();
    }
  }

 /**
  * Create an instance of LegalEntityCapability given an JSON string
  *
  * @param jsonString JSON string
  * @return An instance of LegalEntityCapability
  * @throws IOException if the JSON string is invalid with respect to LegalEntityCapability
  */
  public static LegalEntityCapability fromJson(String jsonString) throws IOException {
    return JSON.getGson().fromJson(jsonString, LegalEntityCapability.class);
  }

 /**
  * Convert an instance of LegalEntityCapability to an JSON string
  *
  * @return JSON string
  */
  public String toJson() {
    return JSON.getGson().toJson(this);
  }
}

