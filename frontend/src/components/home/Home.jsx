import "./Home.scss";

import React from "react";
import { Container } from "reactstrap";

import { ContentSection } from "@greedybear/gb-ui";

import { PUBLIC_URL, VERSION } from "../../constants/environment";
import { NewsWidget } from "./NewsWidget";

const versionText = VERSION;
// const versionText = "v1.0.0";
const logoBgImg = `url('${PUBLIC_URL}/greedybear.png')`;

function Home() {
  console.debug("Home rendered!");

  return (
    <>
      {/* BG Image */}
      <Container fluid id="home__bgImg" style={{ backgroundImage: logoBgImg }}>
        {versionText && (
          <h2
            id="home__versionText"
            className="text-accent"
            data-glitch={versionText}
          >
            {versionText}
          </h2>
        )}
      </Container>
      {/* Content */}
      <Container id="home__content" className="mt-2">
        <ContentSection className="bg-body shadow lead text-center">
          The project goal is to extract data of the attacks detected by a TPOT
          or a cluster of them and to generate some feeds that can be used to
          prevent and detect attacks.
        </ContentSection>
        <br />

        <h5 className="text-gradient">GreedyBear News</h5>
        <ContentSection>
          <NewsWidget />
        </ContentSection>
      </Container>
    </>
  );
}

export default Home;
