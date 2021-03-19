// this file will be overwritten by the lumino node when running inside flask webapp
const backendUrl='http://localhost:5001';
const nodeAddress = '0x4E7eA0919a88f9103e6eE5323D24A1073d79fb0D';
const rnsDomain = 'dev.rsk.co';
const chainEndpoint = 'http://localhost:4444';

window.luminoUrl = backendUrl;
window.nodeAddress= nodeAddress;
window.rnsDomain = rnsDomain;
window.chainEndpoint = chainEndpoint;
