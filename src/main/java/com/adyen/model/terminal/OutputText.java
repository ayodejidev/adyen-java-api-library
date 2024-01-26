/*
 * Adyen Terminal API
 *
 * The version of the OpenAPI document: 1
 * 
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */


package com.adyen.model.terminal;

import java.util.Objects;
import java.util.Arrays;
import java.util.Map;
import java.util.HashMap;
import com.adyen.model.terminal.Alignment;
import com.adyen.model.terminal.CharacterHeight;
import com.adyen.model.terminal.CharacterStyle;
import com.adyen.model.terminal.CharacterWidth;
import com.adyen.model.terminal.Color;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonTypeName;
import com.fasterxml.jackson.annotation.JsonValue;
import io.swagger.annotations.ApiModel;
import io.swagger.annotations.ApiModelProperty;
import com.fasterxml.jackson.annotation.JsonPropertyOrder;
import com.fasterxml.jackson.core.JsonProcessingException;


/**
 * It conveys Information related to the content of the text message and its format. All the data elements related to the format of the text to display or print are parameters valid for the whole Text content. Content of text message to display or print.
 */
@ApiModel(description = "It conveys Information related to the content of the text message and its format. All the data elements related to the format of the text to display or print are parameters valid for the whole Text content. Content of text message to display or print.")
@JsonPropertyOrder({
  OutputText.JSON_PROPERTY_TEXT,
  OutputText.JSON_PROPERTY_CHARACTER_SET,
  OutputText.JSON_PROPERTY_FONT,
  OutputText.JSON_PROPERTY_START_ROW,
  OutputText.JSON_PROPERTY_START_COLUMN,
  OutputText.JSON_PROPERTY_COLOR,
  OutputText.JSON_PROPERTY_CHARACTER_WIDTH,
  OutputText.JSON_PROPERTY_CHARACTER_HEIGHT,
  OutputText.JSON_PROPERTY_CHARACTER_STYLE,
  OutputText.JSON_PROPERTY_ALIGNMENT,
  OutputText.JSON_PROPERTY_END_OF_LINE_FLAG
})

public class OutputText {
  public static final String JSON_PROPERTY_TEXT = "Text";
  private String text;

  public static final String JSON_PROPERTY_CHARACTER_SET = "CharacterSet";
  private Integer characterSet;

  public static final String JSON_PROPERTY_FONT = "Font";
  private String font;

  public static final String JSON_PROPERTY_START_ROW = "StartRow";
  private Integer startRow;

  public static final String JSON_PROPERTY_START_COLUMN = "StartColumn";
  private Integer startColumn;

  public static final String JSON_PROPERTY_COLOR = "Color";
  private Color color;

  public static final String JSON_PROPERTY_CHARACTER_WIDTH = "CharacterWidth";
  private CharacterWidth characterWidth;

  public static final String JSON_PROPERTY_CHARACTER_HEIGHT = "CharacterHeight";
  private CharacterHeight characterHeight;

  public static final String JSON_PROPERTY_CHARACTER_STYLE = "CharacterStyle";
  private CharacterStyle characterStyle;

  public static final String JSON_PROPERTY_ALIGNMENT = "Alignment";
  private Alignment alignment;

  public static final String JSON_PROPERTY_END_OF_LINE_FLAG = "EndOfLineFlag";
  private Boolean endOfLineFlag = true;

  public OutputText() { 
  }

  public OutputText text(String text) {
    this.text = text;
    return this;
  }

   /**
   * Get text
   * @return text
  **/
  @ApiModelProperty(required = true, value = "")
  @JsonProperty(JSON_PROPERTY_TEXT)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)

  public String getText() {
    return text;
  }


 /**
  * text
  *
  * @param text
  */ 
  @JsonProperty(JSON_PROPERTY_TEXT)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)
  public void setText(String text) {
    this.text = text;
  }


  public OutputText characterSet(Integer characterSet) {
    this.characterSet = characterSet;
    return this;
  }

   /**
   * Get characterSet
   * @return characterSet
  **/
  @ApiModelProperty(value = "")
  @JsonProperty(JSON_PROPERTY_CHARACTER_SET)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)

  public Integer getCharacterSet() {
    return characterSet;
  }


 /**
  * characterSet
  *
  * @param characterSet
  */ 
  @JsonProperty(JSON_PROPERTY_CHARACTER_SET)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)
  public void setCharacterSet(Integer characterSet) {
    this.characterSet = characterSet;
  }


  public OutputText font(String font) {
    this.font = font;
    return this;
  }

   /**
   * Get font
   * @return font
  **/
  @ApiModelProperty(value = "")
  @JsonProperty(JSON_PROPERTY_FONT)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)

  public String getFont() {
    return font;
  }


 /**
  * font
  *
  * @param font
  */ 
  @JsonProperty(JSON_PROPERTY_FONT)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)
  public void setFont(String font) {
    this.font = font;
  }


  public OutputText startRow(Integer startRow) {
    this.startRow = startRow;
    return this;
  }

   /**
   * Get startRow
   * minimum: 1
   * maximum: 500
   * @return startRow
  **/
  @ApiModelProperty(value = "")
  @JsonProperty(JSON_PROPERTY_START_ROW)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)

  public Integer getStartRow() {
    return startRow;
  }


 /**
  * startRow
  *
  * @param startRow
  */ 
  @JsonProperty(JSON_PROPERTY_START_ROW)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)
  public void setStartRow(Integer startRow) {
    this.startRow = startRow;
  }


  public OutputText startColumn(Integer startColumn) {
    this.startColumn = startColumn;
    return this;
  }

   /**
   * Get startColumn
   * minimum: 1
   * maximum: 500
   * @return startColumn
  **/
  @ApiModelProperty(value = "")
  @JsonProperty(JSON_PROPERTY_START_COLUMN)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)

  public Integer getStartColumn() {
    return startColumn;
  }


 /**
  * startColumn
  *
  * @param startColumn
  */ 
  @JsonProperty(JSON_PROPERTY_START_COLUMN)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)
  public void setStartColumn(Integer startColumn) {
    this.startColumn = startColumn;
  }


  public OutputText color(Color color) {
    this.color = color;
    return this;
  }

   /**
   * Get color
   * @return color
  **/
  @ApiModelProperty(value = "")
  @JsonProperty(JSON_PROPERTY_COLOR)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)

  public Color getColor() {
    return color;
  }


 /**
  * color
  *
  * @param color
  */ 
  @JsonProperty(JSON_PROPERTY_COLOR)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)
  public void setColor(Color color) {
    this.color = color;
  }


  public OutputText characterWidth(CharacterWidth characterWidth) {
    this.characterWidth = characterWidth;
    return this;
  }

   /**
   * Get characterWidth
   * @return characterWidth
  **/
  @ApiModelProperty(value = "")
  @JsonProperty(JSON_PROPERTY_CHARACTER_WIDTH)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)

  public CharacterWidth getCharacterWidth() {
    return characterWidth;
  }


 /**
  * characterWidth
  *
  * @param characterWidth
  */ 
  @JsonProperty(JSON_PROPERTY_CHARACTER_WIDTH)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)
  public void setCharacterWidth(CharacterWidth characterWidth) {
    this.characterWidth = characterWidth;
  }


  public OutputText characterHeight(CharacterHeight characterHeight) {
    this.characterHeight = characterHeight;
    return this;
  }

   /**
   * Get characterHeight
   * @return characterHeight
  **/
  @ApiModelProperty(value = "")
  @JsonProperty(JSON_PROPERTY_CHARACTER_HEIGHT)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)

  public CharacterHeight getCharacterHeight() {
    return characterHeight;
  }


 /**
  * characterHeight
  *
  * @param characterHeight
  */ 
  @JsonProperty(JSON_PROPERTY_CHARACTER_HEIGHT)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)
  public void setCharacterHeight(CharacterHeight characterHeight) {
    this.characterHeight = characterHeight;
  }


  public OutputText characterStyle(CharacterStyle characterStyle) {
    this.characterStyle = characterStyle;
    return this;
  }

   /**
   * Get characterStyle
   * @return characterStyle
  **/
  @ApiModelProperty(value = "")
  @JsonProperty(JSON_PROPERTY_CHARACTER_STYLE)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)

  public CharacterStyle getCharacterStyle() {
    return characterStyle;
  }


 /**
  * characterStyle
  *
  * @param characterStyle
  */ 
  @JsonProperty(JSON_PROPERTY_CHARACTER_STYLE)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)
  public void setCharacterStyle(CharacterStyle characterStyle) {
    this.characterStyle = characterStyle;
  }


  public OutputText alignment(Alignment alignment) {
    this.alignment = alignment;
    return this;
  }

   /**
   * Get alignment
   * @return alignment
  **/
  @ApiModelProperty(value = "")
  @JsonProperty(JSON_PROPERTY_ALIGNMENT)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)

  public Alignment getAlignment() {
    return alignment;
  }


 /**
  * alignment
  *
  * @param alignment
  */ 
  @JsonProperty(JSON_PROPERTY_ALIGNMENT)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)
  public void setAlignment(Alignment alignment) {
    this.alignment = alignment;
  }


  public OutputText endOfLineFlag(Boolean endOfLineFlag) {
    this.endOfLineFlag = endOfLineFlag;
    return this;
  }

   /**
   * Get endOfLineFlag
   * @return endOfLineFlag
  **/
  @ApiModelProperty(value = "")
  @JsonProperty(JSON_PROPERTY_END_OF_LINE_FLAG)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)

  public Boolean getEndOfLineFlag() {
    return endOfLineFlag;
  }


 /**
  * endOfLineFlag
  *
  * @param endOfLineFlag
  */ 
  @JsonProperty(JSON_PROPERTY_END_OF_LINE_FLAG)
  @JsonInclude(value = JsonInclude.Include.USE_DEFAULTS)
  public void setEndOfLineFlag(Boolean endOfLineFlag) {
    this.endOfLineFlag = endOfLineFlag;
  }


  /**
   * Return true if this OutputText object is equal to o.
   */
  @Override
  public boolean equals(Object o) {
    if (this == o) {
      return true;
    }
    if (o == null || getClass() != o.getClass()) {
      return false;
    }
    OutputText outputText = (OutputText) o;
    return Objects.equals(this.text, outputText.text) &&
        Objects.equals(this.characterSet, outputText.characterSet) &&
        Objects.equals(this.font, outputText.font) &&
        Objects.equals(this.startRow, outputText.startRow) &&
        Objects.equals(this.startColumn, outputText.startColumn) &&
        Objects.equals(this.color, outputText.color) &&
        Objects.equals(this.characterWidth, outputText.characterWidth) &&
        Objects.equals(this.characterHeight, outputText.characterHeight) &&
        Objects.equals(this.characterStyle, outputText.characterStyle) &&
        Objects.equals(this.alignment, outputText.alignment) &&
        Objects.equals(this.endOfLineFlag, outputText.endOfLineFlag);
  }

  @Override
  public int hashCode() {
    return Objects.hash(text, characterSet, font, startRow, startColumn, color, characterWidth, characterHeight, characterStyle, alignment, endOfLineFlag);
  }

  @Override
  public String toString() {
    StringBuilder sb = new StringBuilder();
    sb.append("class OutputText {\n");
    sb.append("    text: ").append(toIndentedString(text)).append("\n");
    sb.append("    characterSet: ").append(toIndentedString(characterSet)).append("\n");
    sb.append("    font: ").append(toIndentedString(font)).append("\n");
    sb.append("    startRow: ").append(toIndentedString(startRow)).append("\n");
    sb.append("    startColumn: ").append(toIndentedString(startColumn)).append("\n");
    sb.append("    color: ").append(toIndentedString(color)).append("\n");
    sb.append("    characterWidth: ").append(toIndentedString(characterWidth)).append("\n");
    sb.append("    characterHeight: ").append(toIndentedString(characterHeight)).append("\n");
    sb.append("    characterStyle: ").append(toIndentedString(characterStyle)).append("\n");
    sb.append("    alignment: ").append(toIndentedString(alignment)).append("\n");
    sb.append("    endOfLineFlag: ").append(toIndentedString(endOfLineFlag)).append("\n");
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

/**
   * Create an instance of OutputText given an JSON string
   *
   * @param jsonString JSON string
   * @return An instance of OutputText
   * @throws JsonProcessingException if the JSON string is invalid with respect to OutputText
   */
  public static OutputText fromJson(String jsonString) throws JsonProcessingException {
    return JSON.getMapper().readValue(jsonString, OutputText.class);
  }
/**
  * Convert an instance of OutputText to an JSON string
  *
  * @return JSON string
  */
  public String toJson() throws JsonProcessingException {
    return JSON.getMapper().writeValueAsString(this);
  }
}
