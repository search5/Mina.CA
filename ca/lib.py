import paginate


def paginate_link_tag(item):
    """
    Create an A-HREF tag that points to another page usable in paginate.
    """
    item['attrs'] = {'class': 'page-link'}
    a_tag = paginate.Page.default_link_tag(item)

    if item['type'] == 'current_page':
        return paginate.make_html_tag('li', paginate.make_html_tag('a', a_tag), **{"class": "page-item active"})
    return paginate.make_html_tag("li", a_tag, **{"class": "page-item"})
