import React from "react";
import { ContentSection } from "@greedybear/gb-ui";
import { Spinner } from "reactstrap";
import { GREEDYBEAR_NEWS_URL } from "../../constants/api";

export const NewsWidget = React.memo(() => {
  const [data, setData] = React.useState([]);
  const [loading, setLoading] = React.useState(true);
  const [error, setError] = React.useState(false);

  const formatDate = (dateStr) => {
    if (!dateStr) return "";

    const date = new Date(dateStr);
    if (isNaN(date.getTime())) return dateStr;

    const day = date.getDate();
    const month = date.toLocaleDateString("en-US", { month: "short" });
    const year = date.getFullYear();

    const ordinals = ["th", "st", "nd", "rd"];
    const v = day % 100;
    const ordinal = ordinals[(v - 20) % 10] || ordinals[v] || ordinals[0];

    return `${day}${ordinal} ${month} ${year}`;
  };

  React.useEffect(() => {
    fetch(GREEDYBEAR_NEWS_URL)
      .then((response) => {
        if (!response.ok) {
          throw new Error(`HTTP error ${response.status}`);
        }
        return response.json();
      })
      .then(setData)
      .catch((err) => {
        console.error("Error fetching news:", err);
        setError(true);
      })
      .finally(() => setLoading(false));
  }, []);

  if (loading) {
    return (
      <div className="d-flex justify-content-center align-items-center py-4">
        <Spinner size="sm" className="me-2" />
        <span className="text-muted">Loading news...</span>
      </div>
    );
  }

  if (error) {
    return (
      <div className="d-flex justify-content-center align-items-center py-4">
        <span className="text-muted">
          Unable to load news. Please try again later.
        </span>
      </div>
    );
  }

  if (data.length === 0) {
    return (
      <div className="d-flex justify-content-center align-items-center py-4">
        <span className="text-muted">No news available at the moment.</span>
      </div>
    );
  }

  return (
    <>
      {data.map((item) => (
        <ContentSection key={item.link} className="border-dark bg-body mb-3">
          {item.date && (
            <small className="text-muted float-end">
              {formatDate(item.date)}
            </small>
          )}

          <h5 className="text-secondary">{item.title}</h5>
          <p className="mb-2 text-muted">{item.subtext}</p>

          <a
            className="link-ul-primary"
            href={item.link}
            target="_blank"
            rel="noopener noreferrer"
            aria-label={`Read more about ${item.title}`}
          >
            Read more
          </a>
        </ContentSection>
      ))}
    </>
  );
});
