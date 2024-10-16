from pypdf import PdfReader

def extract_pdf_data(pdf_path):
    reader = PdfReader(pdf_path)
    
    abstract = ""
    keywords = ""
    citations = ""
    
    # Extract text from the second page (assuming zero-based index)
    if len(reader.pages) > 1:
        second_page = reader.pages[1].extract_text()
        
        # Extract Abstract
        abstract_start = second_page.lower().find("abstract")
        keywords_start = second_page.lower().find("keywords")
        
        if abstract_start != -1:
            if keywords_start != -1:
                abstract = second_page[abstract_start + len("abstract"):keywords_start].strip()
            else:
                abstract = second_page[abstract_start + len("abstract"):].strip()

        # Extract Keywords
        if keywords_start != -1:
            keywords = second_page[keywords_start + len("keywords"):].strip().split("\n")[0]

    # Extract Citations from the last few pages
    citations_start = False
    for page_num in range(len(reader.pages) - 1, 0, -1):
        page_text = reader.pages[page_num].extract_text()
        if "references" in page_text.lower() or "citations" in page_text.lower():
            citations_start = True
        if citations_start:
            citations += page_text.strip() + "\n"

    citations = citations.strip()

    print(f"Extracted Abstract: {abstract}")
    print(f"Extracted Keywords: {keywords}")
    print(f"Extracted Citations: {citations}")

    return {
        'abstract': abstract,
        'keywords': keywords,
        'citations': citations
    }
