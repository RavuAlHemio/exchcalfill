use msswap::{EXCHANGE_MESSAGES_NS_URI, EXCHANGE_TYPES_NS_URI, SOAP_NS_URI, xot_ext::{NodeExt, XotExt}};
use xot::{Node, Xot, output::xml::Parameters};

use crate::model::{Calendar, FolderId, NewEvent};


pub(crate) fn search_for_calendars() -> Vec<u8> {
    let mut xot = Xot::new();
    let soap_doc = xot.create_exchange_soap_doc(true);

    // we need this for timezone smartness
    let req_version = xot.create_element_ns(soap_doc.t_ns, "RequestServerVersion");
    xot.set_attribute_value(req_version, "Version", "Exchange2016");
    xot.append(soap_doc.soap_header.unwrap(), req_version).unwrap();

    let find_folder = xot.create_element_ns(soap_doc.m_ns, "FindFolder");
    xot.set_attribute_value(find_folder, "Traversal", "Shallow");
    xot.append(soap_doc.soap_body, find_folder).unwrap();

    let folder_shape = xot.create_element_ns(soap_doc.m_ns, "FolderShape");
    xot.append(find_folder, folder_shape).unwrap();

    let base_shape = xot.create_text_element_ns(soap_doc.t_ns, "BaseShape", "IdOnly");
    xot.append(folder_shape, base_shape).unwrap();

    let add_props = xot.create_element_ns(soap_doc.t_ns, "AdditionalProperties");
    xot.append(folder_shape, add_props).unwrap();

    let name_field_uri = xot.create_element_ns(soap_doc.t_ns, "FieldURI");
    xot.set_attribute_value(name_field_uri, "FieldURI", "folder:DisplayName");
    xot.append(add_props, name_field_uri).unwrap();

    let class_field_uri = xot.create_element_ns(soap_doc.t_ns, "FieldURI");
    xot.set_attribute_value(class_field_uri, "FieldURI", "folder:FolderClass");
    xot.append(add_props, class_field_uri).unwrap();

    let restriction = xot.create_element_ns(soap_doc.m_ns, "Restriction");
    xot.append(find_folder, restriction).unwrap();

    let equals = xot.create_element_ns(soap_doc.t_ns, "IsEqualTo");
    xot.append(restriction, equals).unwrap();

    let field_uri = xot.create_element_ns(soap_doc.t_ns, "FieldURI");
    xot.set_attribute_value(field_uri, "FieldURI", "folder:FolderClass");
    xot.append(equals, field_uri).unwrap();

    let fuoc = xot.create_element_ns(soap_doc.t_ns, "FieldURIOrConstant");
    xot.append(equals, fuoc).unwrap();

    let constant = xot.create_element_ns(soap_doc.t_ns, "Constant");
    xot.set_attribute_value(constant, "Value", "IPF.Appointment");
    xot.append(fuoc, constant).unwrap();

    let parent_folder_ids = xot.create_element_ns(soap_doc.m_ns, "ParentFolderIds");
    xot.append(find_folder, parent_folder_ids).unwrap();

    let dist_folder_id = xot.create_element_ns(soap_doc.t_ns, "DistinguishedFolderId");
    xot.set_attribute_value(dist_folder_id, "Id", "msgfolderroot");
    xot.append(parent_folder_ids, dist_folder_id).unwrap();

    let mut buf = Vec::new();
    xot.serialize_xml_write(Parameters::default(), soap_doc.document, &mut buf)
        .expect("failed to serialize XML");
    buf
}

pub(crate) fn obtain_some_calendar_entry(folder_id: &FolderId) -> Vec<u8> {
    let mut xot = Xot::new();
    let soap_doc = xot.create_exchange_soap_doc(true);

    // we need this for timezone smartness
    let req_version = xot.create_element_ns(soap_doc.t_ns, "RequestServerVersion");
    xot.set_attribute_value(req_version, "Version", "Exchange2016");
    xot.append(soap_doc.soap_header.unwrap(), req_version).unwrap();

    let find_folder = xot.create_element_ns(soap_doc.m_ns, "FindItem");
    xot.set_attribute_value(find_folder, "Traversal", "Shallow");
    xot.append(soap_doc.soap_body, find_folder).unwrap();

    let item_shape = xot.create_element_ns(soap_doc.m_ns, "ItemShape");
    xot.append(find_folder, item_shape).unwrap();

    let base_shape = xot.create_text_element_ns(soap_doc.t_ns, "BaseShape", "AllProperties");
    xot.append(item_shape, base_shape).unwrap();

    let parent_folder_ids = xot.create_element_ns(soap_doc.m_ns, "ParentFolderIds");
    xot.append(find_folder, parent_folder_ids).unwrap();

    let dist_folder_id = xot.create_element_ns(soap_doc.t_ns, "FolderId");
    xot.set_attribute_value(dist_folder_id, "Id", &folder_id.id);
    xot.set_attribute_value(dist_folder_id, "ChangeKey", &folder_id.change_key);
    xot.append(parent_folder_ids, dist_folder_id).unwrap();

    let mut buf = Vec::new();
    xot.serialize_xml_write(Parameters::default(), soap_doc.document, &mut buf)
        .expect("failed to serialize XML");
    buf
}

pub(crate) fn extract_found_calendars(xml_bytes: Vec<u8>) -> Vec<Calendar> {
    let mut xot = Xot::new();
    let doc = xot.parse_bytes(&xml_bytes)
        .expect("failed to parse XML");

    let soap_ns = xot.namespace(SOAP_NS_URI).unwrap();
    let m_ns = xot.namespace(EXCHANGE_MESSAGES_NS_URI).unwrap();
    let t_ns = xot.namespace(EXCHANGE_TYPES_NS_URI).unwrap();

    let envelope_n = xot.add_name_ns("Envelope", soap_ns);
    let body_n = xot.add_name_ns("Body", soap_ns);
    let find_folder_resp_n = xot.add_name_ns("FindFolderResponse", m_ns);
    let resp_msgs_n = xot.add_name_ns("ResponseMessages", m_ns);
    let find_folder_resp_msg_n = xot.add_name_ns("FindFolderResponseMessage", m_ns);
    let root_folder_n = xot.add_name_ns("RootFolder", m_ns);
    let folders_n = xot.add_name_ns("Folders", t_ns);
    let calendar_folder_n = xot.add_name_ns("CalendarFolder", t_ns);
    let folder_id_n = xot.add_name_ns("FolderId", t_ns);
    let display_name_n = xot.add_name_ns("DisplayName", t_ns);
    let id_n = xot.add_name("Id");
    let change_key_n = xot.add_name("ChangeKey");

    let calendar_nodes: Vec<Node> = doc
        .first_child_element_named(&xot, envelope_n)
        .expect("no soap:Envelope")
        .first_child_element_named(&xot, body_n)
        .expect("no soap:Body")
        .first_child_element_named(&xot, find_folder_resp_n)
        .expect("no m:FindFolderResponse")
        .first_child_element_named(&xot, resp_msgs_n)
        .expect("no m:ResponseMessages")
        .first_child_element_named(&xot, find_folder_resp_msg_n)
        .expect("no m:FindFolderResponseMessage")
        .first_child_element_named(&xot, root_folder_n)
        .expect("no m:RootFolder")
        .first_child_element_named(&xot, folders_n)
        .expect("no t:Folders")
        .child_elements_named(&xot, calendar_folder_n);

    let mut calendars = Vec::new();
    for calendar_node in calendar_nodes {
        let folder_id_elem = calendar_node
            .children(&xot).into_iter()
            .filter(|c| xot.is_element_named(*c, folder_id_n))
            .nth(0).expect("no t:FolderId");
        let folder_id = xot.get_attribute(folder_id_elem, id_n)
            .expect("no Id attribute");
        let change_key = xot.get_attribute(folder_id_elem, change_key_n)
            .expect("no ChangeKey attribute");

        let display_name_text = calendar_node
            .children(&xot).into_iter()
            .filter(|c| xot.is_element_named(*c, display_name_n))
            .nth(0).expect("no t:DisplayName")
            .children(&xot).into_iter()
            .filter(|c| xot.is_text(*c))
            .nth(0).expect("no text node");
        let display_name_str = xot.text_str(display_name_text).unwrap();

        let folder_id_obj = FolderId::new(
            folder_id.to_owned(),
            change_key.to_owned(),
        );

        calendars.push(Calendar::new(
            folder_id_obj,
            display_name_str.to_owned(),
        ));
    }

    calendars.sort_unstable_by_key(|c| c.display_name.clone());

    calendars
}

pub(crate) fn create_event(event: &NewEvent, folder_id: &FolderId) -> Vec<u8> {
    let mut xot = Xot::new();
    let soap_doc = xot.create_exchange_soap_doc(true);

    // we need this for timezone smartness
    let req_version = xot.create_element_ns(soap_doc.t_ns, "RequestServerVersion");
    xot.set_attribute_value(req_version, "Version", "Exchange2016");
    xot.append(soap_doc.soap_header.unwrap(), req_version).unwrap();

    let create_item = xot.create_element_ns(soap_doc.m_ns, "CreateItem");
    // the following attribute ensures that an appointment and not a meeting is created:
    xot.set_attribute_value(create_item, "SendMeetingInvitations", "SendToNone");
    xot.append(soap_doc.soap_body, create_item).unwrap();

    let target_folder_id = xot.create_element_ns(soap_doc.m_ns, "SavedItemFolderId");
    xot.append(create_item, target_folder_id).unwrap();

    let folder_id_elem = xot.create_element_ns(soap_doc.t_ns, "FolderId");
    xot.set_attribute_value(folder_id_elem, "Id", &folder_id.id);
    xot.set_attribute_value(folder_id_elem, "ChangeKey", &folder_id.change_key);
    xot.append(target_folder_id, folder_id_elem).unwrap();

    let items = xot.create_element_ns(soap_doc.m_ns, "Items");
    xot.append(create_item, items).unwrap();

    let calendar_item = xot.create_element_ns(soap_doc.t_ns, "CalendarItem");
    xot.append(items, calendar_item).unwrap();

    let subject = xot.create_text_element_ns(soap_doc.t_ns, "Subject", &event.title);
    xot.append(calendar_item, subject).unwrap();

    if let Some(loc) = &event.location {
        let location = xot.create_text_element_ns(soap_doc.t_ns, "Location", loc);
        xot.append(calendar_item, location).unwrap();
    }

    let reminder_is_set = xot.create_text_element_ns(soap_doc.t_ns, "ReminderIsSet", "false");
    xot.append(calendar_item, reminder_is_set).unwrap();

    let start = xot.create_text_element_ns(
        soap_doc.t_ns,
        "Start",
        &event.start_time.format("%Y-%m-%dT%H:%M:%S").to_string(),
    );
    xot.append(calendar_item, start).unwrap();

    let end = xot.create_text_element_ns(
        soap_doc.t_ns,
        "End",
        &event.end_time.format("%Y-%m-%dT%H:%M:%S").to_string(),
    );
    xot.append(calendar_item, end).unwrap();

    let is_all_day = xot.create_text_element_ns(
        soap_doc.t_ns,
        "IsAllDayEvent",
        "false",
    );
    xot.append(calendar_item, is_all_day).unwrap();

    let legacy_free_busy = xot.create_text_element_ns(
        soap_doc.t_ns,
        "LegacyFreeBusyStatus",
        event.free_busy_status.as_exchange_str(),
    );
    xot.append(calendar_item, legacy_free_busy).unwrap();

    let mut buf = Vec::new();
    xot.serialize_xml_write(Parameters::default(), soap_doc.document, &mut buf)
        .expect("failed to serialize XML");
    buf
}

pub(crate) fn extract_success(xml_bytes: Vec<u8>) {
    let mut xot = Xot::new();
    let doc = xot.parse_bytes(&xml_bytes)
        .expect("failed to parse XML");

    let soap_ns = xot.namespace(SOAP_NS_URI).unwrap();
    let m_ns = xot.namespace(EXCHANGE_MESSAGES_NS_URI).unwrap();

    let envelope_n = xot.add_name_ns("Envelope", soap_ns);
    let body_n = xot.add_name_ns("Body", soap_ns);
    let cir_n = xot.add_name_ns("CreateItemResponse", m_ns);
    let resp_msgs_n = xot.add_name_ns("ResponseMessages", m_ns);
    let cirm_n = xot.add_name_ns("CreateItemResponseMessage", m_ns);
    let resp_code_n = xot.add_name_ns("ResponseCode", m_ns);
    let resp_class_n = xot.add_name("ResponseClass");

    let response_nodes: Vec<Node> = doc
        .first_child_element_named(&xot, envelope_n)
        .expect("no soap:Envelope")
        .first_child_element_named(&xot, body_n)
        .expect("no soap:Body")
        .first_child_element_named(&xot, cir_n)
        .expect("no m:CreateItemResponse")
        .first_child_element_named(&xot, resp_msgs_n)
        .expect("no m:ResponseMessages")
        .children(&xot).into_iter()
        .filter(|c| xot.is_element_named(*c, cirm_n))
        .collect();

    for response_node in response_nodes {
        let code_string = response_node
            .first_child_element_named(&xot, resp_code_n).expect("no m:ResponseCode")
            .child_text(&xot).expect("m:ResponseCode does not only have text children");

        let resp_class = xot.get_attribute(response_node, resp_class_n).unwrap();
        if resp_class != "Success" || code_string != "NoError" {
            println!("response class: {}, response code: {}", resp_class, code_string);
            println!("{:?}", std::str::from_utf8(&xml_bytes));
        }
        return;
    }
}
