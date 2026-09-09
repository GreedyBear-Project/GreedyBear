import React from "react";
import { Pagination, PaginationItem, PaginationLink } from "reactstrap";

// constants
const INITIAL_SLICE = 5;
const ELLIPSES_TEXT = "...";

// component
function Paginator(props) {
  const { pageOptions, onPaginate, pageIndex, ...rest } = props;

  const [slice, setSlice] = React.useState(INITIAL_SLICE);

  React.useEffect(() => {
    if (pageIndex + slice > pageOptions.length) {
      setSlice(INITIAL_SLICE);
    }
  }, [pageIndex, pageOptions, slice, setSlice]);

  const numPages = pageOptions.length - 1;
  const lowerSlice = Math.max(pageIndex - INITIAL_SLICE, 0);
  const upperSlice = Math.min(
    pageIndex + slice + INITIAL_SLICE,
    pageOptions.length,
  );
  let slicedPages = pageOptions.slice(lowerSlice, pageIndex + INITIAL_SLICE);
  if (slice > INITIAL_SLICE) {
    slicedPages = [
      ...slicedPages,
      ELLIPSES_TEXT,
      ...pageOptions.slice(pageIndex + slice, upperSlice),
    ];
  }

  return (
    <Pagination aria-label="Data Table Pagination" {...rest}>
      {/* first */}
      {pageIndex !== 0 && (
        <PaginationItem>
          <PaginationLink first onClick={() => onPaginate(0)} />
        </PaginationItem>
      )}
      {/* nums */}
      {slicedPages.map((i) => (
        <PaginationItem
          active={i === pageIndex}
          key={i}
          disabled={i === ELLIPSES_TEXT}
        >
          <PaginationLink onClick={() => onPaginate(i)}>
            {i === ELLIPSES_TEXT ? i : i + 1}
          </PaginationLink>
        </PaginationItem>
      ))}
      {/* ellipses */}
      {upperSlice < numPages && (
        <PaginationItem
          title="load more"
          onClick={() => setSlice((s) => s + INITIAL_SLICE)}
        >
          <PaginationLink>{ELLIPSES_TEXT}</PaginationLink>
        </PaginationItem>
      )}
      {/* last */}
      {pageIndex !== numPages && (
        <PaginationItem>
          <PaginationLink last onClick={() => onPaginate(numPages)} />
        </PaginationItem>
      )}
    </Pagination>
  );
}

export default React.memo(Paginator);
