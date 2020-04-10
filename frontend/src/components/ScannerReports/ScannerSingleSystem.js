import React, { Component } from 'react';
import { Container, Row, Col, Alert, Table } from 'reactstrap'
// import { FontAwesomeIcon } from '@fortawesome/react-fontawesome'
// import { faInfoCircle, faUndo } from '@fortawesome/free-solid-svg-icons'
// import { Link } from 'react-router-dom'
import API from '../../api'

class ScannerSingleSystem extends Component {
    constructor(props) {
        super(props)
        this.state = {openPorts: {}, closedPorts: []}
        this.loadScanningInfo()
    }

    async loadScanningInfo() {
        var response = await API.getLocalSystemStatus(this.props.ipaddress)
        if (response.success) {
            this.setState(response.data)
        }

    }

    render() {
        return (
            <Container fluid={true}>
                <Row>
                    <Col sm="12"><h3>{this.props.ipaddress}</h3></Col>
                </Row>
                <Row>
                <Col sm="12">
                    {(Object.keys(this.state.openPorts).length > 0  || this.state.closedPorts.length > 0) ? (
                        <Table>
                            <thead>
                                <tr>
                                    <th>Port</th>
                                    <th>State</th>
                                    <th>Product</th>
                                    <th>Version</th>
                                </tr>
                            </thead>
                            <tbody>
                                {
                                    Object.keys(this.state.openPorts).map((port, i) => {
                                        var portData = this.state.openPorts[port]
                                        return (
                                            <tr>
                                                <td>{port}</td>
                                                <td>Open</td>
                                                <td>{portData.prod_name}</td>
                                                <td>{(portData.version === 0) ? "unknown" : portData.version.toFixed(2) }</td>
                                            </tr>
                                        )
                                    })
                                }
                                {
                                    this.state.closedPorts.map((port, i) => {
                                        return (
                                            <tr>
                                                <td>{port}</td>
                                                <td>Closed</td>
                                                <td>-</td>
                                                <td>-</td>
                                            </tr>
                                        ) 
                                    })
                                }
                            <tr>
                            <td colspan="4"><strong>Last Scanned: </strong>{this.state.lastScanTime}</td>
                            </tr>
                            </tbody>
                        </Table>
                    ) : (<Alert color="warning">No Ports Data to display for this system!</Alert>)}
                    </Col>
                </Row>

            </Container>
        )

    }
}

export default ScannerSingleSystem