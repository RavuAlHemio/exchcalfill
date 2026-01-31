use xot::{NameId, NamespaceId, Node, PrefixId, ValueType, Xot};

use crate::{EXCHANGE_MESSAGES_NS_URI, EXCHANGE_TYPES_NS_URI, SOAP_NS_URI};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SoapDoc {
    pub document: Node,
    pub soap_header: Option<Node>,
    pub soap_body: Node,

    pub soap_ns: NamespaceId,
    pub t_ns: NamespaceId,
    pub m_ns: NamespaceId,
    pub soap_p: PrefixId,
    pub t_p: PrefixId,
    pub m_p: PrefixId,
}

pub trait XotExt {
    fn create_exchange_soap_doc(&mut self, add_header: bool) -> SoapDoc;
    fn create_element_ns(&mut self, ns: NamespaceId, name: &str) -> Node;
    fn create_text_element_ns(&mut self, ns: NamespaceId, name: &str, text: &str) -> Node;
    fn set_attribute_value(&mut self, node: Node, attribute: &str, value: &str);
    fn is_element_named(&self, node: Node, name: NameId) -> bool;
}
impl XotExt for Xot {
    fn create_exchange_soap_doc(&mut self, add_header: bool) -> SoapDoc {
        let soap_ns = self.add_namespace(SOAP_NS_URI);
        let t_ns = self.add_namespace(EXCHANGE_TYPES_NS_URI);
        let m_ns = self.add_namespace(EXCHANGE_MESSAGES_NS_URI);
        let soap_p = self.add_prefix("soap");
        let t_p = self.add_prefix("t");
        let m_p = self.add_prefix("m");

        let envelope_n = self.add_name_ns("Envelope", soap_ns);
        let envelope = self.new_element(envelope_n);
        self.set_namespace(envelope, soap_p, soap_ns);
        self.set_namespace(envelope, t_p, t_ns);
        self.set_namespace(envelope, m_p, m_ns);
        let document = self.new_document_with_element(envelope)
            .expect("failed to create document");

        let header = if add_header {
            let header_n = self.add_name_ns("Header", soap_ns);
            let header = self.new_element(header_n);
            self.append(envelope, header).unwrap();
            Some(header)
        } else {
            None
        };

        let body_n = self.add_name_ns("Body", soap_ns);
        let body = self.new_element(body_n);
        self.append(envelope, body).unwrap();

        SoapDoc {
            document,
            soap_header: header,
            soap_body: body,

            soap_ns,
            t_ns,
            m_ns,
            soap_p,
            t_p,
            m_p,
        }
    }

    fn create_element_ns(&mut self, ns: NamespaceId, name: &str) -> Node {
        let name = self.add_name_ns(name, ns);
        let elem = self.new_element(name);
        elem
    }

    fn create_text_element_ns(&mut self, ns: NamespaceId, name: &str, text: &str) -> Node {
        let elem = self.create_element_ns(ns, name);
        let text = self.new_text(text);
        self.append(elem, text).unwrap();
        elem
    }

    fn set_attribute_value(&mut self, node: Node, attribute: &str, value: &str) {
        let name = self.add_name(attribute);
        self.set_attribute(node, name, value);
    }

    fn is_element_named(&self, node: Node, name: NameId) -> bool {
        match self.element(node) {
            Some(e) => {
                e.name() == name
            },
            None => false,
        }
    }
}


pub trait NodeExt {
    fn children(&self, xot: &Xot) -> Vec<Node>;

    fn child_elements_named(&self, xot: &Xot, name: NameId) -> Vec<Node> {
        self
            .children(xot).into_iter()
            .filter(|c| xot.is_element_named(*c, name))
            .collect()
    }

    fn first_child_element_named(&self, xot: &Xot, name: NameId) -> Option<Node> {
        let mut elems = self.child_elements_named(xot, name);
        if elems.len() == 0 {
            None
        } else {
            Some(elems.swap_remove(0))
        }
    }

    fn child_text(&self, xot: &Xot) -> Option<String>;
}
impl NodeExt for Node {
    fn children(&self, xot: &Xot) -> Vec<Node> {
        xot
            .children(*self)
            .into_iter()
            .collect()
    }

    fn child_text(&self, xot: &Xot) -> Option<String> {
        let mut ret = String::new();
        for child in xot.children(*self) {
            match xot.value_type(child) {
                ValueType::Document => return None,
                ValueType::Element => return None,
                ValueType::Text => {
                    ret.push_str(xot.text_str(child).unwrap());
                },
                ValueType::ProcessingInstruction => return None,
                ValueType::Comment => {},
                ValueType::Attribute => {},
                ValueType::Namespace => {},
            }
        }
        Some(ret)
    }
}
