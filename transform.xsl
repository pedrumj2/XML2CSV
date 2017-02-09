<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
<xsl:template match="TestbedMonJun14Flows">
<xsl:value-of select="appName"/><xsl:text>,</xsl:text>
<xsl:value-of select="totalSourceBytes"/><xsl:text>,</xsl:text>
<xsl:value-of select="totalDestinationBytes"/><xsl:text>,</xsl:text>
<xsl:value-of select="totalDestinationPackets"/><xsl:text>,</xsl:text>
<xsl:value-of select="totalSourcePackets"/><xsl:text>,</xsl:text>
<xsl:value-of select="direction"/><xsl:text>,</xsl:text>
<xsl:value-of select="source"/><xsl:text>,</xsl:text>
<xsl:value-of select="protocolName"/><xsl:text>,</xsl:text>
<xsl:value-of select="sourcePort"/><xsl:text>,</xsl:text>
<xsl:value-of select="destination"/><xsl:text>,</xsl:text>
<xsl:value-of select="destinationPort"/><xsl:text>,</xsl:text>
<xsl:value-of select="startDateTime"/><xsl:text>,</xsl:text>
<xsl:value-of select="stopDateTime"/><xsl:text>,</xsl:text>
<xsl:value-of select="Tag"/>

</xsl:template>
</xsl:stylesheet>

