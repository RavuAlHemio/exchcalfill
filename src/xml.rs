use sxd_document::Package;
use sxd_document::dom::Element;
use sxd_document::parser;
use sxd_document::writer::Writer;
use sxd_xpath::{Context, Factory, Value, XPath};
use sxd_xpath::nodeset::{Node, Nodeset};

use crate::model::{Calendar, FolderId, NewEvent};


const SOAP_NS_URI: &str = "http://schemas.xmlsoap.org/soap/envelope/";
const EXCHANGE_TYPES_NS_URI: &str = "http://schemas.microsoft.com/exchange/services/2006/types";
const EXCHANGE_MESSAGES_NS_URI: &str = "http://schemas.microsoft.com/exchange/services/2006/messages";


trait IntoNodeset<'d> {
    fn into_nodeset(self) -> Option<Nodeset<'d>>;
}
impl<'d> IntoNodeset<'d> for Value<'d> {
    fn into_nodeset(self) -> Option<Nodeset<'d>> {
        match self {
            Value::Nodeset(ns) => Some(ns),
            _ => None,
        }
    }
}

trait GimmeXPath {
    fn gimme_xpath(&self, expression: &str) -> XPath;
}
impl GimmeXPath for Factory {
    fn gimme_xpath(&self, expression: &str) -> XPath {
        self.build(expression)
            .expect("failed to parse XPath expression")
            .expect("XPath expression is empty")
    }
}

trait EvaluateNodeset {
    fn evaluate_nodeset<'d, N: Into<Node<'d>>>(&self, context: &Context<'d>, node: N) -> Nodeset<'d>;

    fn evaluate_element<'d, N: Into<Node<'d>>>(&self, context: &Context<'d>, node: N) -> Element<'d> {
        self.evaluate_nodeset(context, node)
            .document_order_first()
            .expect("no node found")
            .element()
            .expect("not an element")
    }

    fn evaluate_text<'d, N: Into<Node<'d>>>(&self, context: &Context<'d>, node: N) -> &'d str {
        self.evaluate_nodeset(context, node)
            .document_order_first()
            .expect("no node found")
            .text()
            .expect("not a text node")
            .text()
    }
}
impl EvaluateNodeset for XPath {
    fn evaluate_nodeset<'d, N: Into<Node<'d>>>(&self, context: &Context<'d>, node: N) -> Nodeset<'d> {
        self.evaluate(context, node)
            .expect("failed to evaluate XPath expression")
            .into_nodeset()
            .expect("XPath result is not a nodeset")
    }
}


pub(crate) fn search_for_calendars() -> Vec<u8> {
    let find_calendar_folders_package = Package::new();
    let find_calendar_folders = find_calendar_folders_package.as_document();

    let envelope = find_calendar_folders.create_element("soap:Envelope");
    envelope.set_attribute_value("xmlns:soap", SOAP_NS_URI);
    envelope.set_attribute_value("xmlns:t", EXCHANGE_TYPES_NS_URI);
    envelope.set_attribute_value("xmlns:m", EXCHANGE_MESSAGES_NS_URI);
    find_calendar_folders.root().append_child(envelope);

    let header = find_calendar_folders.create_element("soap:Header");
    envelope.append_child(header);

    let version = find_calendar_folders.create_element("t:RequestServerVersion");
    version.set_attribute_value("Version", "Exchange2016");
    header.append_child(version);

    let body = find_calendar_folders.create_element("soap:Body");
    envelope.append_child(body);

    let find_folder = find_calendar_folders.create_element("m:FindFolder");
    find_folder.set_attribute_value("Traversal", "Shallow");
    body.append_child(find_folder);

    let folder_shape = find_calendar_folders.create_element("m:FolderShape");
    find_folder.append_child(folder_shape);

    let base_shape = find_calendar_folders.create_element("t:BaseShape");
    base_shape.set_text("IdOnly");
    folder_shape.append_child(base_shape);

    let add_props = find_calendar_folders.create_element("t:AdditionalProperties");
    folder_shape.append_child(add_props);

    let name_field_uri = find_calendar_folders.create_element("t:FieldURI");
    name_field_uri.set_attribute_value("FieldURI", "folder:DisplayName");
    add_props.append_child(name_field_uri);

    let class_field_uri = find_calendar_folders.create_element("t:FieldURI");
    class_field_uri.set_attribute_value("FieldURI", "folder:FolderClass");
    add_props.append_child(class_field_uri);

    let restriction = find_calendar_folders.create_element("m:Restriction");
    find_folder.append_child(restriction);

    let equals = find_calendar_folders.create_element("t:IsEqualTo");
    restriction.append_child(equals);

    let field_uri = find_calendar_folders.create_element("t:FieldURI");
    field_uri.set_attribute_value("FieldURI", "folder:FolderClass");
    equals.append_child(field_uri);

    let fuoc = find_calendar_folders.create_element("t:FieldURIOrConstant");
    equals.append_child(fuoc);

    let constant = find_calendar_folders.create_element("t:Constant");
    constant.set_attribute_value("Value", "IPF.Appointment");
    fuoc.append_child(constant);

    let parent_folder_ids = find_calendar_folders.create_element("m:ParentFolderIds");
    find_folder.append_child(parent_folder_ids);

    let dist_folder_id = find_calendar_folders.create_element("t:DistinguishedFolderId");
    dist_folder_id.set_attribute_value("Id", "msgfolderroot");
    parent_folder_ids.append_child(dist_folder_id);

    let mut buf = Vec::new();
    let wr = Writer::new()
        .set_write_encoding(true);
    wr.format_document(&find_calendar_folders, &mut buf)
        .expect("failed to serialize XML");
    buf
}

pub(crate) fn obtain_some_calendar_entry(folder_id: &FolderId) -> Vec<u8> {
    let find_calendar_folders_package = Package::new();
    let find_calendar_folders = find_calendar_folders_package.as_document();

    let envelope = find_calendar_folders.create_element("soap:Envelope");
    envelope.set_attribute_value("xmlns:soap", SOAP_NS_URI);
    envelope.set_attribute_value("xmlns:t", EXCHANGE_TYPES_NS_URI);
    envelope.set_attribute_value("xmlns:m", EXCHANGE_MESSAGES_NS_URI);
    find_calendar_folders.root().append_child(envelope);

    let header = find_calendar_folders.create_element("soap:Header");
    envelope.append_child(header);

    let version = find_calendar_folders.create_element("t:RequestServerVersion");
    version.set_attribute_value("Version", "Exchange2016");
    header.append_child(version);

    let body = find_calendar_folders.create_element("soap:Body");
    envelope.append_child(body);

    let find_folder = find_calendar_folders.create_element("m:FindItem");
    find_folder.set_attribute_value("Traversal", "Shallow");
    body.append_child(find_folder);

    let item_shape = find_calendar_folders.create_element("m:ItemShape");
    find_folder.append_child(item_shape);

    let base_shape = find_calendar_folders.create_element("t:BaseShape");
    base_shape.set_text("AllProperties");
    item_shape.append_child(base_shape);

    let parent_folder_ids = find_calendar_folders.create_element("m:ParentFolderIds");
    find_folder.append_child(parent_folder_ids);

    let dist_folder_id = find_calendar_folders.create_element("t:FolderId");
    dist_folder_id.set_attribute_value("Id", &folder_id.id);
    dist_folder_id.set_attribute_value("ChangeKey", &folder_id.change_key);
    parent_folder_ids.append_child(dist_folder_id);

    let mut buf = Vec::new();
    let wr = Writer::new()
        .set_write_encoding(true);
    wr.format_document(&find_calendar_folders, &mut buf)
        .expect("failed to serialize XML");
    buf
}

pub(crate) fn extract_found_calendars(xml_bytes: Vec<u8>) -> Vec<Calendar> {
    let xml_string = String::from_utf8(xml_bytes)
        .expect("failed to decode XML als UTF-8");
    let xml_package = parser::parse(&xml_string)
        .expect("failed to parse XML");
    let doc = xml_package.as_document();

    let mut xpath_ctx = Context::new();
    xpath_ctx.set_namespace("soap", SOAP_NS_URI);
    xpath_ctx.set_namespace("t", EXCHANGE_TYPES_NS_URI);
    xpath_ctx.set_namespace("m", EXCHANGE_MESSAGES_NS_URI);

    let xpath_factory = Factory::new();

    let calendars_xpath = xpath_factory.gimme_xpath("/soap:Envelope/soap:Body/m:FindFolderResponse/m:ResponseMessages/m:FindFolderResponseMessage/m:RootFolder/t:Folders/t:CalendarFolder");
    let folder_id_xpath = xpath_factory.gimme_xpath("./t:FolderId");
    let display_name_xpath = xpath_factory.gimme_xpath("./t:DisplayName/text()");

    let calendars_value = calendars_xpath.evaluate_nodeset(&xpath_ctx, doc.root());
    let mut calendars = Vec::new();
    for calendar_node in calendars_value {
        let folder_id_elem = folder_id_xpath.evaluate_element(&xpath_ctx, calendar_node);
        let folder_id = folder_id_elem.attribute_value("Id").expect("no Id attribute");
        let change_key = folder_id_elem.attribute_value("ChangeKey").expect("no ChangeKey attribute");

        let display_name = display_name_xpath.evaluate_text(&xpath_ctx, calendar_node);

        let folder_id_obj = FolderId::new(
            folder_id.to_owned(),
            change_key.to_owned(),
        );

        calendars.push(Calendar::new(
            folder_id_obj,
            display_name.to_owned(),
        ));
    }

    calendars.sort_unstable_by_key(|c| c.display_name.clone());

    calendars
}

pub(crate) fn create_event(event: &NewEvent, folder_id: &FolderId) -> Vec<u8> {
    let create_event_package = Package::new();
    let create_event = create_event_package.as_document();

    let envelope = create_event.create_element("soap:Envelope");
    envelope.set_attribute_value("xmlns:soap", SOAP_NS_URI);
    envelope.set_attribute_value("xmlns:t", EXCHANGE_TYPES_NS_URI);
    envelope.set_attribute_value("xmlns:m", EXCHANGE_MESSAGES_NS_URI);
    create_event.root().append_child(envelope);

    let header = create_event.create_element("soap:Header");
    envelope.append_child(header);

    let version = create_event.create_element("t:RequestServerVersion");
    version.set_attribute_value("Version", "Exchange2016");
    header.append_child(version);

    let body = create_event.create_element("soap:Body");
    envelope.append_child(body);

    let create_item = create_event.create_element("m:CreateItem");
    // the following attribute ensures that an appointment and not a meeting is created:
    create_item.set_attribute_value("SendMeetingInvitations", "SendToNone");
    body.append_child(create_item);

    let target_folder_id = create_event.create_element("m:SavedItemFolderId");
    create_item.append_child(target_folder_id);

    let folder_id_elem = create_event.create_element("t:FolderId");
    folder_id_elem.set_attribute_value("Id", &folder_id.id);
    folder_id_elem.set_attribute_value("ChangeKey", &folder_id.change_key);
    target_folder_id.append_child(folder_id_elem);

    let items = create_event.create_element("m:Items");
    create_item.append_child(items);

    let calendar_item = create_event.create_element("t:CalendarItem");
    items.append_child(calendar_item);

    let subject = create_event.create_element("t:Subject");
    subject.set_text(&event.title);
    calendar_item.append_child(subject);

    if let Some(loc) = &event.location {
        let location = create_event.create_element("t:Location");
        location.set_text(&loc);
        calendar_item.append_child(location);
    }

    let reminder_is_set = create_event.create_element("t:ReminderIsSet");
    reminder_is_set.set_text("false");
    calendar_item.append_child(reminder_is_set);

    let start = create_event.create_element("t:Start");
    start.set_text(&event.start_time.format("%Y-%m-%dT%H:%M:%S").to_string());
    calendar_item.append_child(start);

    let end = create_event.create_element("t:End");
    end.set_text(&event.end_time.format("%Y-%m-%dT%H:%M:%S").to_string());
    calendar_item.append_child(end);

    let is_all_day = create_event.create_element("t:IsAllDayEvent");
    is_all_day.set_text("false");
    calendar_item.append_child(is_all_day);

    let legacy_free_busy = create_event.create_element("t:LegacyFreeBusyStatus");
    legacy_free_busy.set_text("Busy");
    calendar_item.append_child(legacy_free_busy);

    let mut buf = Vec::new();
    let wr = Writer::new()
        .set_write_encoding(true);
    wr.format_document(&create_event, &mut buf)
        .expect("failed to serialize XML");
    buf
}
