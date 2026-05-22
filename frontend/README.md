# GreedyBear - frontend

Built with [gb-ui](https://github.com/GreedyBear-Project/gb-ui).

## Design thesis

- GreedyBear specific:
  - components should be added to `src/components`.
  - general hooks should be added to `src/hooks`.
  - zustand stores hooks should be added to `src/stores`.

## Directory Structure

```
public/                                   public static assets
|- icons/                                 icons/favicon
|- index.html/                            root HTML file
src/                                      source code
|- components/                            pages and components
|  |- auth/                               `certego_saas.apps.auth` (login, logout pages)
|  |- dashboard/                          dashboard page and charts
|  |- home/                               landing/home page
|  |- Routes.jsx                          lazy route-component mappings
|- constants/                             constant values
|  |- api.js                              API URLs
|  |- environment.js                      environment variables
|  |- index.js                            GreedyBear specific constants
|- hooks/                                 react hooks
|- layouts/                               header, main, footer containers
|- stores/                                zustand stores hooks
|- styles/                                scss files
|- wrappers/                              Higher-Order components
|- App.jsx                                App component
|- index.jsx                              Root JS file (ReactDOM renderer)
```

## Local Development Environment

The frontend inside the docker containers does not hot-reload, so
you need to use `CRA dev server` on your host machine to serve pages when doing development on the frontend, using docker nginx only as API source.

- Start GreedyBear containers (see [docs](https://github.com/GreedyBear-Project/GreedyBear/wiki/Installation)). Original dockerized app is accessible on `http://localhost:80`

- If you have not `node-js` installed, you have to do that. Follow the guide [here](https://www.digitalocean.com/community/tutorials/how-to-install-node-js-on-ubuntu-20-04). We tested this with NodeJS >=16.6

- Install npm packages locally

```bash
cd ./frontend && npm install
```

- Start CRA dev server:

```bash
npm start
```

- Now you can access the auto-reloading frontend on `http://localhost:3001`. It acts as proxy for API requests to original app web server.

- JS app main configs are available in `package.json` and `enviroments.js`.


