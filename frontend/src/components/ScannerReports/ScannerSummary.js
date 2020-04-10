import React, { Component } from 'react';
import { Spinner, Container, Row, Col, Alert, Table, Button, Card, CardHeader, CardBody } from 'reactstrap'
import { FontAwesomeIcon } from '@fortawesome/react-fontawesome'
import { faInfoCircle, faUndo } from '@fortawesome/free-solid-svg-icons'
import { Link } from 'react-router-dom'
import { Doughnut } from 'react-chartjs-2';
import { LightenDarkenColor } from 'lighten-darken-color';
import API from '../../api'
var randomColor = require('random-color');
class ScannerSummary extends Component {
    constructor(props) {
        super(props)
        this.state = { isLoading: true, error: null, systemsData: {}, totalSystems: 0, upCount: 0, osCount: {} }
        this.loadSystems = this.loadSystems.bind(this)
    }
    async componentDidMount() {
        await this.loadSystems()
    }

    async loadSystems() {
        this.setState({ 'isLoading': true })
        var response = await API.getAllLocalSystems()
        if (response.success) {
            var systems = response.data
            var systemsInfo = {}
            var upCount = 0
            var osCount = {}
            for (var ipaddress of systems) {
                response = await API.getLocalSystemStatus(ipaddress)
                console.log(response)
                if (response.success === false) {
                    systemsInfo[ipaddress] = null
                } else {
                    var data = response.data
                    systemsInfo[ipaddress] = data
                    if (data.up === true) {
                        upCount += 1
                    }
                    if (osCount[data.os]) {
                        osCount[data.os]++
                    } else {
                        osCount[data.os] = 1
                    }
                }
            }
            this.setState({ error: "", systemsData: systemsInfo, totalSystems: systems.length, upCount: upCount, osCount: osCount, isLoading: false })
        } else {
            this.setState({ error: response.error, isLoading: false })
            return null
        }
    }

    render() {
        var loading = (this.state.isLoading) ? <Row><Col sm={{ size: 2, offset: 5 }}><Spinner color="info" /></Col></Row> : null;
        var data = (!this.state.isLoading) ? ((this.state.error) ? <Alert color="warning">{this.state.error}</Alert> : null) : null

        if (this.state.totalSystems > 0) {
            var colorPairs = this.getColorPairs(2)
            var statusDoughnut = {
                labels: [
                    'Up',
                    'Down',
                ],
                datasets: [{
                    data: [this.state.upCount, this.state.totalSystems - this.state.upCount],
                    backgroundColor: colorPairs.normal,
                    hoverBackgroundColor: colorPairs.hover
                }]
            };
            var colorPair = this.getColorPairs(Object.keys(this.state.osCount).length)
            var osDoughnut = {
                labels: Object.keys(this.state.osCount),
                datasets: [{
                    data: Object.values(this.state.osCount),
                    backgroundColor: colorPair.normal,
                    hoverBackgroundColor: colorPair.hover
                }]
            };
            data = (<>
                <Container>
                    <Row className="mb-2">
                        <Col>
                            <Alert color="info" style={{ lineHeight: '2rem' }}><FontAwesomeIcon icon={faInfoCircle}></FontAwesomeIcon> {this.state.upCount} out of {this.state.totalSystems} system(s) are up.<Button color="warning" className="float-right" onClick={this.loadSystems}><FontAwesomeIcon icon={faUndo}></FontAwesomeIcon> Reload</Button></Alert>
                        </Col>
                    </Row>
                    <Row fluid={"true"}>
                        <Col md="8">

                            <Table>
                                <thead>
                                    <tr>
                                        <th>#</th>
                                        <th>IP Address</th>
                                        <th>Status</th>
                                        <th>OS Family</th>
                                        <th>Port Scan Results</th>
                                        <th>Last Scan</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    {
                                        Object.keys(this.state.systemsData).map((ipaddress, i) => {
                                            data = this.state.systemsData[ipaddress]
                                            if (data == null) {
                                                return (<></>)
                                            }
                                            console.log(data)
                                            return (
                                                <tr key={"tr-" + i}>
                                                    <th scope="row">{i + 1}</th>
                                                    <td>{ipaddress}</td>
                                                    <td>{(data.up) ? <>Online</> : <>Offline</>}</td>
                                                    <td>{(data.up) ? data.os : <>-</>}</td>
                                                    <td>{(data.up) ? <>{Object.keys(data.openPorts).length + " open and " + data.closedPorts.length + " closed port(s)"}</> : <>-</>}</td>
                                                    <td>{data.lastScanTime}</td>
                                                </tr>

                                            )
                                        })
                                    }
                                </tbody>
                            </Table>
                        </Col>
                        <Col md="4">
                            <Row className="mb-2">
                                <Card>
                                    <CardHeader>Status Graph</CardHeader>
                                    <CardBody>
                                        <Doughnut data={statusDoughnut} />
                                    </CardBody>
                                </Card>
                            </Row>
                            <Row>
                                <Card>
                                    <CardHeader>Operating Systems Graph</CardHeader>
                                    <CardBody>
                                        <Doughnut data={osDoughnut} />
                                    </CardBody>
                                </Card>
                            </Row>
                        </Col>
                    </Row>
                </Container>
            </>)
        } else {
            data = (<>
                <Alert color="info">No system found in you IP Pool. Please add systems from sidebar <Link to="/settings/agent"><i>Settings &gt; Local Agent</i></Link></Alert>
            </>)
        }

        return ( <>
                    {(loading) ? loading : data}
        </>)
    }
    getColorPairs(count) {
        var colArr = []
        var hoverArr = []
        for (var i = 0; i < count; i++) {
            var col = randomColor().hexString()
            colArr.push(col)
            hoverArr.push(LightenDarkenColor(col, 60))
        }
        return { normal: colArr, hover: hoverArr }


    }
}



export default ScannerSummary