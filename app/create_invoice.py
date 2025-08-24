from lxml import etree
from lxml.etree import QName

def create_invoice_xml(data: dict, output_path):
    NSMAP = {
        None: "urn:oasis:names:specification:ubl:schema:xsd:Invoice-2",
        "cac": "urn:oasis:names:specification:ubl:schema:xsd:CommonAggregateComponents-2",
        "cbc": "urn:oasis:names:specification:ubl:schema:xsd:CommonBasicComponents-2",
        "ext": "urn:oasis:names:specification:ubl:schema:xsd:CommonExtensionComponents-2",
    }

    def make_element(tag, text=None, parent=None, **attributes):
        if ":" in tag:
            prefix, local_name = tag.split(":", 1)
            namespace = NSMAP[prefix]
            el = etree.Element(QName(namespace, local_name), nsmap=NSMAP, **attributes)
        else:
            el = etree.Element(QName(NSMAP[None], tag), nsmap=NSMAP, **attributes)
        if text is not None:
            el.text = str(text)
        if parent is not None:
            parent.append(el)
        return el

    invoice = make_element("Invoice")

    # --- Header (order matters) ---
    make_element("cbc:ProfileID", data["ProfileID"], invoice)
    make_element("cbc:ID", data["ID"], invoice)
    make_element("cbc:CopyIndicator", "false", invoice)  # must be early
    make_element("cbc:UUID", data["UUID"], invoice)
    make_element("cbc:IssueDate", data["IssueDate"], invoice)
    make_element("cbc:IssueTime", data["IssueTime"], invoice)
    make_element("cbc:InvoiceTypeCode", data["InvoiceTypeCode"], invoice, name=data["InvoiceTypeCodeName"])
    make_element("cbc:Note", data["Note"], invoice, languageID="ar")
    make_element("cbc:DocumentCurrencyCode", data["DocumentCurrencyCode"], invoice)
    if data.get("TaxCurrencyCode"):
        make_element("cbc:TaxCurrencyCode", data["TaxCurrencyCode"], invoice)

    # BillingReference
    if data.get("BillingReference"):
        br = make_element("cac:BillingReference", parent=invoice)
        invref = make_element("cac:InvoiceDocumentReference", parent=br)
        make_element("cbc:ID", data["BillingReference"], invref)

    # AdditionalDocumentReference
    for ref in data.get("AdditionalDocumentReferences", []):
        adr = make_element("cac:AdditionalDocumentReference", parent=invoice)
        make_element("cbc:ID", ref["ID"], adr)
        if ref.get("UUID"):
            make_element("cbc:UUID", ref["UUID"], adr)
        if ref.get("Attachment"):
            att = make_element("cac:Attachment", parent=adr)
            make_element(
                "cbc:EmbeddedDocumentBinaryObject",
                ref["Attachment"],
                att,
                mimeCode="text/plain",
                filename=ref.get("FileName", "attachment.txt"),
                characterSetCode="UTF-8",
            )

    # Supplier
    sp_party = make_element("cac:AccountingSupplierParty", parent=invoice)
    sp = make_element("cac:Party", parent=sp_party)
    sp_pid = make_element("cac:PartyIdentification", parent=sp)
    make_element("cbc:ID", data["SupplierCRN"], sp_pid, schemeID=data["SupplierSchemeID"])
    sp_addr = make_element("cac:PostalAddress", parent=sp)
    make_element("cbc:StreetName", data["SupplierStreetName"], sp_addr)
    make_element("cbc:BuildingNumber", data["SupplierBuildingNumber"], sp_addr)
    make_element("cbc:CitySubdivisionName", data["SupplierDistrict"], sp_addr)
    make_element("cbc:CityName", data["SupplierCityName"], sp_addr)
    make_element("cbc:PostalZone", data["SupplierPostalZone"], sp_addr)
    sp_country = make_element("cac:Country", parent=sp_addr)
    make_element("cbc:IdentificationCode", data["SupplierCountryCode"], sp_country, listID="ISO3166-1:Alpha2")
    sp_tax = make_element("cac:PartyTaxScheme", parent=sp)
    make_element("cbc:CompanyID", data["SupplierVAT"], sp_tax)
    sp_taxsch = make_element("cac:TaxScheme", parent=sp_tax)
    make_element("cbc:ID", "VAT", sp_taxsch, schemeID="UN/ECE 5153", schemeAgencyID="6")
    sp_legal = make_element("cac:PartyLegalEntity", parent=sp)
    make_element("cbc:RegistrationName", data["SupplierName"], sp_legal)

    # Customer
    cu_party = make_element("cac:AccountingCustomerParty", parent=invoice)
    cu = make_element("cac:Party", parent=cu_party)
    cu_pid = make_element("cac:PartyIdentification", parent=cu)
    make_element("cbc:ID", data.get("CustomerCRN", "0000000000"), cu_pid, schemeID="CRN")
    cu_addr = make_element("cac:PostalAddress", parent=cu)
    make_element("cbc:StreetName", data["CustomerStreetName"], cu_addr)
    make_element("cbc:BuildingNumber", data["CustomerBuildingNumber"], cu_addr)
    make_element("cbc:CitySubdivisionName", data["CustomerDistrict"], cu_addr)
    make_element("cbc:CityName", data["CustomerCityName"], cu_addr)
    make_element("cbc:PostalZone", data["CustomerPostalZone"], cu_addr)
    cu_country = make_element("cac:Country", parent=cu_addr)
    make_element("cbc:IdentificationCode", data["CustomerCountryCode"], cu_country, listID="ISO3166-1:Alpha2")
    cu_tax = make_element("cac:PartyTaxScheme", parent=cu)
    make_element("cbc:CompanyID", data["CustomerVAT"], cu_tax)
    cu_taxsch = make_element("cac:TaxScheme", parent=cu_tax)
    make_element("cbc:ID", "VAT", cu_taxsch, schemeID="UN/ECE 5153", schemeAgencyID="6")
    cu_legal = make_element("cac:PartyLegalEntity", parent=cu)
    make_element("cbc:RegistrationName", data["CustomerName"], cu_legal)

    # Delivery
    if data.get("DeliveryDate"):
        delivery = make_element("cac:Delivery", parent=invoice)
        make_element("cbc:ActualDeliveryDate", data["DeliveryDate"], delivery)

    # PaymentMeans
    if data.get("PaymentMeansCode"):
        pm = make_element("cac:PaymentMeans", parent=invoice)
        make_element("cbc:PaymentMeansCode", data["PaymentMeansCode"], pm)

    # Document-level AllowanceCharge
    if data.get("AllowanceCharge"):
        ac = make_element("cac:AllowanceCharge", parent=invoice)
        make_element("cbc:ChargeIndicator", str(data.get("AllowanceCharge", {}).get("ChargeIndicator") or "false").lower(), ac)
        make_element("cbc:AllowanceChargeReason", data["AllowanceCharge"]["Reason"], ac)
        make_element("cbc:Amount", data["AllowanceCharge"]["Amount"], ac, currencyID=data["DocumentCurrencyCode"])
        for tc in data["AllowanceCharge"].get("TaxCategories", []):
            tax_cat = make_element("cac:TaxCategory", parent=ac)
            make_element("cbc:ID", tc["ID"], tax_cat, schemeID="UN/ECE 5305", schemeAgencyID="6")
            make_element("cbc:Percent", tc["Percent"], tax_cat)
            tax_scheme = make_element("cac:TaxScheme", parent=tax_cat)
            make_element("cbc:ID", tc["SchemeID"], tax_scheme, schemeID="UN/ECE 5153", schemeAgencyID="6")

    # TaxTotal (one) WITH VAT breakdown (BG-23) — always include to satisfy BR-CO-18/15 and KSA-08
    tax_total = make_element("cac:TaxTotal", parent=invoice)
    make_element("cbc:TaxAmount", data["TaxAmount"], tax_total, currencyID=data["DocumentCurrencyCode"])

    tax_sub = make_element("cac:TaxSubtotal", parent=tax_total)
    make_element("cbc:TaxableAmount", data["TaxExclusiveAmount"], tax_sub, currencyID=data["DocumentCurrencyCode"])
    make_element("cbc:TaxAmount", data["TaxAmount"], tax_sub, currencyID=data["DocumentCurrencyCode"])
    tax_cat = make_element("cac:TaxCategory", parent=tax_sub)
    make_element("cbc:ID", "S", tax_cat, schemeID="UN/ECE 5305", schemeAgencyID="6")
    make_element("cbc:Percent", data.get("TaxPercent", 15.0), tax_cat)
    tax_scheme = make_element("cac:TaxScheme", parent=tax_cat)
    make_element("cbc:ID", "VAT", tax_scheme, schemeID="UN/ECE 5153", schemeAgencyID="6")

    # LegalMonetaryTotal
    legal = make_element("cac:LegalMonetaryTotal", parent=invoice)
    make_element("cbc:LineExtensionAmount", data["LineExtensionAmount"], legal, currencyID=data["DocumentCurrencyCode"])
    make_element("cbc:TaxExclusiveAmount", data["TaxExclusiveAmount"], legal, currencyID=data["DocumentCurrencyCode"])
    make_element("cbc:TaxInclusiveAmount", data["TaxInclusiveAmount"], legal, currencyID=data["DocumentCurrencyCode"])
    make_element("cbc:AllowanceTotalAmount", data.get("AllowanceTotalAmount", 0.00), legal, currencyID=data["DocumentCurrencyCode"])
    make_element("cbc:PrepaidAmount", data.get("PrepaidAmount", 0.00), legal, currencyID=data["DocumentCurrencyCode"])
    make_element("cbc:PayableAmount", data["PayableAmount"], legal, currencyID=data["DocumentCurrencyCode"])

    # Invoice lines (line AllowanceCharge BEFORE Item and Price)
    for line in data.get("InvoiceLines", []):
        il = make_element("cac:InvoiceLine", parent=invoice)
        make_element("cbc:ID", line["ID"], il)
        make_element("cbc:InvoicedQuantity", line["Quantity"], il, unitCode=line["UnitCode"])
        make_element("cbc:LineExtensionAmount", line["LineExtensionAmount"], il, currencyID=data["DocumentCurrencyCode"])

        if line.get("AllowanceCharge"):
            lac = make_element("cac:AllowanceCharge", parent=il)
            make_element("cbc:ChargeIndicator", str(line.get("AllowanceCharge", {}).get("ChargeIndicator") or "false").lower(), lac)
            make_element("cbc:AllowanceChargeReason", line["AllowanceCharge"]["Reason"], lac)
            make_element("cbc:Amount", line["AllowanceCharge"]["Amount"], lac, currencyID=data["DocumentCurrencyCode"])

        item = make_element("cac:Item", parent=il)
        make_element("cbc:Name", line["Name"], item)
        ctc = make_element("cac:ClassifiedTaxCategory", parent=item)
        make_element("cbc:ID", line["TaxCategoryID"], ctc, schemeID="UN/ECE 5305", schemeAgencyID="6")
        make_element("cbc:Percent", line["TaxPercent"], ctc)
        ctc_ts = make_element("cac:TaxScheme", parent=ctc)
        make_element("cbc:ID", "VAT", ctc_ts, schemeID="UN/ECE 5153", schemeAgencyID="6")

        price = make_element("cac:Price", parent=il)
        make_element("cbc:PriceAmount", line["PriceAmount"], price, currencyID=data["DocumentCurrencyCode"])

    etree.ElementTree(invoice).write(output_path, encoding="UTF-8", xml_declaration=True, pretty_print=True)