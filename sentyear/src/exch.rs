use chrono::{DateTime, NaiveDateTime, Utc};
use msswap::{EXCHANGE_MESSAGES_NS_URI, EXCHANGE_TYPES_NS_URI, IdAndChangeKey, SOAP_NS_URI, xot_ext::{NodeExt, XotExt}};
use xot::{Node, Xot};


const EXCHANGE_TIMESTAMP_FORMAT: &str = "%Y-%m-%dT%H:%M:%SZ";


#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct SentItem {
    pub id: IdAndChangeKey,
    pub sent: DateTime<Utc>,
}


pub fn create_request_enumerate_sent_folder(offset: usize) -> (Xot, Node) {
    let mut xot = Xot::new();
    let soap_doc = xot.create_exchange_soap_doc(false);

    let find_item_n = xot.add_name_ns("FindItem", soap_doc.m_ns);
    let find_item_elem = xot.new_element(find_item_n);
    xot.set_attribute_value(find_item_elem, "Traversal", "Shallow");
    xot.append(soap_doc.soap_body, find_item_elem).unwrap();

    let item_shape_n = xot.add_name_ns("ItemShape", soap_doc.m_ns);
    let item_shape_elem = xot.new_element(item_shape_n);
    xot.append(find_item_elem, item_shape_elem).unwrap();

    let base_shape_elem = xot.create_text_element_ns(soap_doc.t_ns, "BaseShape", "IdOnly");
    xot.append(item_shape_elem, base_shape_elem).unwrap();

    let additional_properties_elem = xot.create_element_ns(soap_doc.t_ns, "AdditionalProperties");
    xot.append(item_shape_elem, additional_properties_elem).unwrap();

    let field_uri_sent_elem = xot.create_element_ns(soap_doc.t_ns, "FieldURI");
    xot.set_attribute_value(field_uri_sent_elem, "FieldURI", "item:DateTimeSent");
    xot.append(additional_properties_elem, field_uri_sent_elem).unwrap();

    let pagination_elem = xot.create_element_ns(soap_doc.m_ns, "IndexedPageViewItemView");
    xot.set_attribute_value(pagination_elem, "BasePoint", "Beginning");
    xot.set_attribute_value(pagination_elem, "Offset", &format!("{}", offset));
    xot.append(find_item_elem, pagination_elem).unwrap();

    let parent_folder_ids_elem = xot.create_element_ns(soap_doc.m_ns, "ParentFolderIds");
    xot.append(find_item_elem, parent_folder_ids_elem).unwrap();

    let dist_folder_id_elem = xot.create_element_ns(soap_doc.t_ns, "DistinguishedFolderId");
    xot.set_attribute_value(dist_folder_id_elem, "Id", "sentitems");
    xot.append(parent_folder_ids_elem, dist_folder_id_elem).unwrap();

    (xot, soap_doc.document)
}


pub fn create_request_get_known_folder(known_folder_id: &str) -> (Xot, Node) {
    let mut xot = Xot::new();
    let soap_doc = xot.create_exchange_soap_doc(false);

    let get_folder_elem = xot.create_element_ns(soap_doc.m_ns, "GetFolder");
    xot.append(soap_doc.soap_body, get_folder_elem).unwrap();

    let folder_shape_elem = xot.create_element_ns(soap_doc.m_ns, "FolderShape");
    xot.append(get_folder_elem, folder_shape_elem).unwrap();

    let base_shape_elem = xot.create_text_element_ns(soap_doc.t_ns, "BaseShape", "IdOnly");
    xot.append(folder_shape_elem, base_shape_elem).unwrap();

    let parent_folder_ids_elem = xot.create_element_ns(soap_doc.m_ns, "FolderIds");
    xot.append(get_folder_elem, parent_folder_ids_elem).unwrap();

    let dist_folder_id_elem = xot.create_element_ns(soap_doc.t_ns, "DistinguishedFolderId");
    xot.set_attribute_value(dist_folder_id_elem, "Id", known_folder_id);
    xot.append(parent_folder_ids_elem, dist_folder_id_elem).unwrap();

    (xot, soap_doc.document)
}


pub fn create_request_find_folder(base_folder_id: &IdAndChangeKey, name: &str) -> (Xot, Node) {
    let mut xot = Xot::new();
    let soap_doc = xot.create_exchange_soap_doc(false);

    let find_folder_elem = xot.create_element_ns(soap_doc.m_ns, "FindFolder");
    xot.set_attribute_value(find_folder_elem, "Traversal", "Deep");
    xot.append(soap_doc.soap_body, find_folder_elem).unwrap();

    let folder_shape_elem = xot.create_element_ns(soap_doc.m_ns, "FolderShape");
    xot.append(find_folder_elem, folder_shape_elem).unwrap();

    let base_shape_elem = xot.create_text_element_ns(soap_doc.t_ns, "BaseShape", "IdOnly");
    xot.append(folder_shape_elem, base_shape_elem).unwrap();

    let restriction_elem = xot.create_element_ns(soap_doc.m_ns, "Restriction");
    xot.append(find_folder_elem, restriction_elem).unwrap();

    let is_equal_to_elem = xot.create_element_ns(soap_doc.t_ns, "IsEqualTo");
    xot.append(restriction_elem, is_equal_to_elem).unwrap();

    let field_uri_elem = xot.create_element_ns(soap_doc.t_ns, "FieldURI");
    xot.set_attribute_value(field_uri_elem, "FieldURI", "folder:DisplayName");
    xot.append(is_equal_to_elem, field_uri_elem).unwrap();

    let field_uri_or_constant_elem = xot.create_element_ns(soap_doc.t_ns, "FieldURIOrConstant");
    xot.append(is_equal_to_elem, field_uri_or_constant_elem).unwrap();

    let constant_elem = xot.create_element_ns(soap_doc.t_ns, "Constant");
    xot.set_attribute_value(constant_elem, "Value", name);
    xot.append(field_uri_or_constant_elem, constant_elem).unwrap();

    let parent_folder_ids_elem = xot.create_element_ns(soap_doc.m_ns, "ParentFolderIds");
    xot.append(find_folder_elem, parent_folder_ids_elem).unwrap();

    let folder_id_elem = xot.create_element_ns(soap_doc.t_ns, "FolderId");
    base_folder_id.set_on_xml_element(&mut xot, folder_id_elem);
    xot.append(parent_folder_ids_elem, folder_id_elem).unwrap();

    (xot, soap_doc.document)
}


pub fn create_request_move_item(item_ids: &[IdAndChangeKey], dest_folder_id: &IdAndChangeKey) -> (Xot, Node) {
    let mut xot = Xot::new();
    let soap_doc = xot.create_exchange_soap_doc(false);

    let move_item_elem = xot.create_element_ns(soap_doc.m_ns, "MoveItem");
    xot.append(soap_doc.soap_body, move_item_elem).unwrap();

    let to_folder_id_elem = xot.create_element_ns(soap_doc.m_ns, "ToFolderId");
    xot.append(move_item_elem, to_folder_id_elem).unwrap();

    let folder_id_elem = xot.create_element_ns(soap_doc.t_ns, "FolderId");
    dest_folder_id.set_on_xml_element(&mut xot, folder_id_elem);
    xot.append(to_folder_id_elem, folder_id_elem).unwrap();

    let item_ids_elem = xot.create_element_ns(soap_doc.m_ns, "ItemIds");
    xot.append(move_item_elem, item_ids_elem).unwrap();

    for item_id in item_ids {
        let item_id_elem = xot.create_element_ns(soap_doc.t_ns, "ItemId");
        item_id.set_on_xml_element(&mut xot, item_id_elem);
        xot.append(item_ids_elem, item_id_elem).unwrap();
    }

    (xot, soap_doc.document)
}

pub fn extract_response_enumerate_sent_folder<'d>(xot: &mut Xot, doc: Node) -> (bool, Vec<SentItem>) {
    let soap_ns = xot.namespace(SOAP_NS_URI).unwrap();
    let t_ns = xot.namespace(EXCHANGE_TYPES_NS_URI).unwrap();
    let m_ns = xot.namespace(EXCHANGE_MESSAGES_NS_URI).unwrap();

    let envelope_n = xot.add_name_ns("Envelope", soap_ns);
    let body_n = xot.add_name_ns("Body", soap_ns);
    let fir_n = xot.add_name_ns("FindItemResponse", m_ns);
    let resp_msgs_n = xot.add_name_ns("ResponseMessages", m_ns);
    let firm_n = xot.add_name_ns("FindItemResponseMessage", m_ns);
    let root_folder_n = xot.add_name_ns("RootFolder", m_ns);
    let items_n = xot.add_name_ns("Items", t_ns);
    let item_id_n = xot.add_name_ns("ItemId", t_ns);
    let date_time_sent_n = xot.add_name_ns("DateTimeSent", t_ns);
    let includes_last_n = xot.add_name("IncludesLastItemInRange");

    let root_folder_elem = doc
        .first_child_element_named(&xot, envelope_n)
        .expect("no soap:Envelope child found")
        .first_child_element_named(&xot, body_n)
        .expect("no soap:Body child found")
        .first_child_element_named(&xot, fir_n)
        .expect("no m:FindItemResponse child found")
        .first_child_element_named(&xot, resp_msgs_n)
        .expect("no m:ResponseMessages child found")
        .first_child_element_named(&xot, firm_n)
        .expect("no m:FindItemResponseMessage child found")
        .first_child_element_named(&xot, root_folder_n)
        .expect("no m:RootFolder child found");
    let is_last_str = xot.get_attribute(root_folder_elem, includes_last_n)
        .expect("m:RootFolder is missing IncludesLastItemInRange attribute");
    let is_last = match is_last_str {
        "true" => true,
        "false" => false,
        other => panic!("unexpected value for IncludesLastItemInRange attribute in m:RootFolder: {}", other),
    };

    let items_elem = root_folder_elem
        .first_child_element_named(&xot, items_n)
        .expect("no t:Items child found");

    let items_children: Vec<Node> = items_elem
        .children(&xot).into_iter()
        .filter(|c| xot.is_element(*c))
        .collect();
    let mut sent_items = Vec::new();
    for item in items_children {
        let id_elem = item
            .first_child_element_named(&xot, item_id_n)
            .expect("t:Items child without t:ItemId element");
        let item_id = IdAndChangeKey::from_xml_element(xot, id_elem)
            .expect("t:Items child without t:ItemId values");
        let sent_timestamp_string = item
            .first_child_element_named(&xot, date_time_sent_n)
            .expect("t:Items child without t:DateTimeSent element")
            .child_text(&xot).expect("Items child t:DateTimeSent does not only contain text children");
        let sent_timestamp = NaiveDateTime::parse_from_str(&sent_timestamp_string, EXCHANGE_TIMESTAMP_FORMAT)
            .expect("failed to parse Exchange timestamp")
            .and_utc();
        sent_items.push(SentItem {
            id: item_id,
            sent: sent_timestamp,
        });
    }

    (is_last, sent_items)
}

pub fn extract_response_get_folder(xot: &mut Xot, doc: Node) -> Option<IdAndChangeKey> {
    let soap_ns = xot.namespace(SOAP_NS_URI).unwrap();
    let t_ns = xot.namespace(EXCHANGE_TYPES_NS_URI).unwrap();
    let m_ns = xot.namespace(EXCHANGE_MESSAGES_NS_URI).unwrap();

    let envelope_n = xot.add_name_ns("Envelope", soap_ns);
    let body_n = xot.add_name_ns("Body", soap_ns);
    let gfr_n = xot.add_name_ns("GetFolderResponse", m_ns);
    let resp_msgs_n = xot.add_name_ns("ResponseMessages", m_ns);
    let gfrm_n = xot.add_name_ns("GetFolderResponseMessage", m_ns);
    let folders_n = xot.add_name_ns("Folders", m_ns);
    let folder_id_n = xot.add_name_ns("FolderId", t_ns);

    let folders_elem = doc
        .first_child_element_named(&xot, envelope_n)
        .expect("no soap:Envelope child found")
        .first_child_element_named(&xot, body_n)
        .expect("no soap:Body child found")
        .first_child_element_named(&xot, gfr_n)
        .expect("no m:GetFolderResponse child found")
        .first_child_element_named(&xot, resp_msgs_n)
        .expect("no m:ResponseMessages child found")
        .first_child_element_named(&xot, gfrm_n)
        .expect("no m:GetFolderResponseMessage child found")
        .first_child_element_named(&xot, folders_n)
        .expect("no m:Folders child found");

    let folders_children: Vec<Node> = folders_elem
        .children(&xot).into_iter()
        .filter(|c| xot.is_element(*c))
        .collect();
    for folder in folders_children {
        let id_elem = folder
            .first_child_element_named(&xot, folder_id_n)
            .expect("m:Folders child without t:FolderId element");
        let folder_id = IdAndChangeKey::from_xml_element(xot, id_elem)
            .expect("Folders child without FolderId values");
        return Some(folder_id);
    }

    None
}

pub fn extract_response_find_folder<'d>(xot: &mut Xot, doc: Node) -> Option<IdAndChangeKey> {
    let soap_ns = xot.namespace(SOAP_NS_URI).unwrap();
    let t_ns = xot.namespace(EXCHANGE_TYPES_NS_URI).unwrap();
    let m_ns = xot.namespace(EXCHANGE_MESSAGES_NS_URI).unwrap();

    let envelope_n = xot.add_name_ns("Envelope", soap_ns);
    let body_n = xot.add_name_ns("Body", soap_ns);
    let ffr_n = xot.add_name_ns("FindFolderResponse", m_ns);
    let resp_msgs_n = xot.add_name_ns("ResponseMessages", m_ns);
    let ffrm_n = xot.add_name_ns("FindFolderResponseMessage", m_ns);
    let root_folder_n = xot.add_name_ns("RootFolder", m_ns);
    let folders_n = xot.add_name_ns("Folders", t_ns);
    let folder_id_n = xot.add_name_ns("FolderId", t_ns);

    let folders_elem = doc
        .first_child_element_named(&xot, envelope_n)
        .expect("no soap:Envelope child found")
        .first_child_element_named(&xot, body_n)
        .expect("no soap:Body child found")
        .first_child_element_named(&xot, ffr_n)
        .expect("no m:FindFolderResponse child found")
        .first_child_element_named(&xot, resp_msgs_n)
        .expect("no m:ResponseMessages child found")
        .first_child_element_named(&xot, ffrm_n)
        .expect("no m:FindFolderResponseMessage child found")
        .first_child_element_named(&xot, root_folder_n)
        .expect("no m:RootFolder child found")
        .first_child_element_named(&xot, folders_n)
        .expect("no t:Folders child found");

    let folders_children: Vec<Node> = folders_elem
        .children(&xot).into_iter()
        .filter(|c| xot.is_element(*c))
        .collect();
    for folder in folders_children {
        let id_elem = folder
            .first_child_element_named(&xot, folder_id_n)
            .expect("t:Folders child without t:FolderId element");
        let folder_id = IdAndChangeKey::from_xml_element(xot, id_elem)
            .expect("t:Folders child without t:FolderId values");
        return Some(folder_id);
    }

    None
}
