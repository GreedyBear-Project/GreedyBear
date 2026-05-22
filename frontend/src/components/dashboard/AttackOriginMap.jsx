import React from "react";
import {
  ComposableMap,
  Geographies,
  Geography,
  ZoomableGroup,
} from "@vnedyalk0v/react19-simple-maps";
import { useTimePickerStore } from "@greedybear/gb-ui";
import countries from "i18n-iso-countries";
import useAttackerCountriesStore from "../../stores/useAttackerCountriesStore";

const WORLD_ATLAS_GEO_URL = `${import.meta.env.BASE_URL}countries-110m.json`;

function lerpColor(a, b, t) {
  const ah = parseInt(a.replace("#", ""), 16);
  const bh = parseInt(b.replace("#", ""), 16);
  const ar = (ah >> 16) & 0xff;
  const ag = (ah >> 8) & 0xff;
  const ab = ah & 0xff;
  const br = (bh >> 16) & 0xff;
  const bg = (bh >> 8) & 0xff;
  const bb = bh & 0xff;
  const rr = Math.round(ar + (br - ar) * t);
  const rg = Math.round(ag + (bg - ag) * t);
  const rb = Math.round(ab + (bb - ab) * t);
  return `rgb(${rr},${rg},${rb})`;
}

const COLOR_EMPTY = "#2a2a3a";
const COLOR_LOW = "#ffffb2";
const COLOR_MID = "#fd8d3c";
const COLOR_HIGH = "#bd0026";

const MapPaths = React.memo(
  ({ geoData, getColor, handleMouseEnter, handleMouseLeave }) => {
    if (!geoData) return null;
    return (
      <Geographies geography={geoData}>
        {({ geographies }) =>
          geographies.map((geo) => (
            <Geography
              key={geo.rsmKey}
              geography={geo}
              fill={getColor(geo.id)}
              stroke="#111"
              strokeWidth={0.4}
              onMouseEnter={(evt) => handleMouseEnter(geo, evt)}
              onMouseLeave={handleMouseLeave}
              style={{
                default: { outline: "none" },
                hover: {
                  outline: "none",
                  fill: "#facc15",
                  transition: "fill 80ms",
                },
                pressed: { outline: "none" },
              }}
            />
          ))
        }
      </Geographies>
    );
  },
);
MapPaths.displayName = "MapPaths";

export default function AttackOriginMap() {
  const { range } = useTimePickerStore();
  const {
    countryDataMap: countryData,
    maxCount,
    loading,
    error,
    fetchData,
  } = useAttackerCountriesStore();

  // TopoJSON is loaded here (bypassing the library's broken URL validator)
  // and passed as an object to <Geographies>.
  const [geoData, setGeoData] = React.useState(null);

  // tooltip state
  const [tooltip, setTooltip] = React.useState({
    visible: false,
    x: 0,
    y: 0,
    name: "",
    count: 0,
  });

  React.useEffect(() => {
    fetchData(range);
  }, [range, fetchData]);

  React.useEffect(() => {
    let cancelled = false;
    fetch(WORLD_ATLAS_GEO_URL)
      .then((r) => {
        if (!r.ok) {
          throw new Error(`Failed to load map data: ${r.status}`);
        }
        return r.json();
      })
      .then((json) => {
        if (!cancelled) setGeoData(json);
      })
      .catch((err) => {
        if (!cancelled) console.error(err);
      });
    return () => {
      cancelled = true;
    };
  }, []);

  const colors = React.useMemo(() => {
    const colorMap = {};
    if (maxCount <= 0) return colorMap;
    for (const [alpha2, count] of Object.entries(countryData)) {
      if (!count) continue;
      const t = Math.sqrt(count / maxCount);
      colorMap[alpha2] =
        t < 0.5
          ? lerpColor(COLOR_LOW, COLOR_MID, t * 2)
          : lerpColor(COLOR_MID, COLOR_HIGH, (t - 0.5) * 2);
    }
    return colorMap;
  }, [countryData, maxCount]);

  /**
   * Resolve fill colour for a geography.
   * geo.id is the ISO 3166-1 numeric code (e.g. "840").
   * i18n-iso-countries converts it to alpha-2 ("US"), which is the key
   * used in countryData — no hand-maintained name table required.
   */
  const getColor = React.useCallback(
    (geoId) => {
      const alpha2 = countries.numericToAlpha2(geoId);
      return (alpha2 && colors[alpha2]) || COLOR_EMPTY;
    },
    [colors],
  );

  const handleMouseEnter = React.useCallback(
    (geo, evt) => {
      const alpha2 = countries.numericToAlpha2(geo.id);
      const count = alpha2 ? (countryData[alpha2] ?? 0) : 0;
      setTooltip({
        visible: true,
        x: evt.clientX,
        y: evt.clientY,
        name: geo.properties.name, // canonical TopoJSON name for display
        count,
      });
    },
    [countryData],
  );

  const handleMouseMove = React.useCallback((evt) => {
    setTooltip((prev) =>
      prev.visible ? { ...prev, x: evt.clientX, y: evt.clientY } : prev,
    );
  }, []);

  const handleMouseLeave = React.useCallback(() => {
    setTooltip((prev) => ({ ...prev, visible: false }));
  }, []);

  if (loading) {
    return (
      <div
        className="d-flex justify-content-center align-items-center text-muted"
        style={{ minHeight: 200 }}
      >
        Loading map…
      </div>
    );
  }

  if (error) {
    return (
      <div
        className="d-flex justify-content-center align-items-center text-muted"
        style={{ minHeight: 200 }}
      >
        {error}
      </div>
    );
  }

  return (
    <div
      style={{
        position: "relative",
        userSelect: "none",
      }}
    >
      {/* Tooltip */}
      {tooltip.visible && (
        <div
          style={{
            position: "fixed",
            left: tooltip.x + 14,
            top: tooltip.y - 10,
            background: "rgba(20,20,32,0.95)",
            border: "1px solid #444",
            borderRadius: 6,
            padding: "6px 10px",
            pointerEvents: "none",
            zIndex: 9999,
            fontSize: 13,
            color: "#eee",
            whiteSpace: "nowrap",
          }}
        >
          <strong>{tooltip.name}</strong>
          {tooltip.count > 0 ? (
            <>
              <br />
              <span style={{ color: "#ff7070" }}>
                {tooltip.count.toLocaleString()} IOC
                {tooltip.count !== 1 ? "s" : ""}
              </span>
            </>
          ) : (
            <>
              <br />
              <span style={{ color: "#888" }}>No data</span>
            </>
          )}
        </div>
      )}

      {/* Map */}
      <div style={{ overflow: "hidden" }}>
        <ComposableMap
          projection="geoNaturalEarth1"
          width={800}
          height={420}
          style={{ width: "100%", height: "auto" }}
          onMouseMove={handleMouseMove}
          onMouseLeave={handleMouseLeave}
        >
          <ZoomableGroup zoom={1} minZoom={0.6} maxZoom={6}>
            <MapPaths
              geoData={geoData}
              getColor={getColor}
              handleMouseEnter={handleMouseEnter}
              handleMouseLeave={handleMouseLeave}
            />
          </ZoomableGroup>
        </ComposableMap>
      </div>

      {/* Colour-scale legend*/}
      {maxCount > 0 && (
        <div
          style={{
            display: "flex",
            alignItems: "center",
            gap: 8,
            justifyContent: "flex-end",
            marginTop: 4,
            paddingRight: 8,
            fontSize: 11,
            color: "#aaa",
          }}
        >
          <span>0</span>
          <div
            style={{
              width: 120,
              height: 10,
              borderRadius: 4,
              background: `linear-gradient(to right, ${COLOR_LOW}, ${COLOR_MID}, ${COLOR_HIGH})`,
            }}
          />
          <span>{maxCount.toLocaleString()}</span>
        </div>
      )}
    </div>
  );
}
